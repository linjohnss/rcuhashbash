/* rcuhashbash: test module for RCU hash-table alorithms.
 * Written by Josh Triplett
 * Mostly lockless random number generator rcu_random from rcutorture, by Paul
 * McKenney and Josh Triplett.
 */
#include <linux/byteorder/swabb.h>
#include <linux/dcache.h>
#include <linux/init.h>
#include <linux/kthread.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/random.h>
#include <linux/rcupdate.h>
#include <linux/seqlock.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/string.h>

MODULE_AUTHOR("Josh Triplett <josh@kernel.org>");
MODULE_DESCRIPTION("RCU hash algorithm test module.");
MODULE_LICENSE("GPL");

static char *reader_type = "rcu"; /* Reader implementation to benchmark */
static char *writer_type = "spinlock"; /* Writer implementation to benchmark */
static int ro = 0; /* Number of reader-only threads; defaults to 0 */
static int rw = -1; /* Number of mixed reader/writer threads; defaults to online CPUs */
static unsigned long rw_writes = 1; /* Number of writes out of each total */
static unsigned long rw_total = 100; /* Total rw operations to divide into readers and writers */
static unsigned long buckets = 1024; /* Number of hash table buckets */
static unsigned long entries = 4096; /* Number of entries initially added */
static unsigned long reader_range = 0; /* Upper bound of reader range */
static unsigned long writer_range = 0; /* Upper bound of writer range */

module_param(reader_type, charp, 0444);
MODULE_PARM_DESC(reader_type, "Hash table reader implementation");
module_param(writer_type, charp, 0444);
MODULE_PARM_DESC(writer_type, "Hash table writer implementation");
module_param(ro, int, 0444);
MODULE_PARM_DESC(ro, "Number of reader-only threads");
module_param(rw, int, 0444);
MODULE_PARM_DESC(rw, "Number of mixed reader/writer threads");
module_param(rw_writes, ulong, 0444);
MODULE_PARM_DESC(rw_writes, "Number of writes out of each total");
module_param(rw_total, ulong, 0444);
MODULE_PARM_DESC(rw_total, "Total rw operations to divide into readers and writers");
module_param(buckets, ulong, 0444);
MODULE_PARM_DESC(buckets, "Number of hash buckets");
module_param(entries, ulong, 0444);
MODULE_PARM_DESC(entries, "Number of hash table entries");
module_param(reader_range, ulong, 0444);
MODULE_PARM_DESC(reader_range, "Upper bound of reader operating range (default 2*entries)");
module_param(writer_range, ulong, 0444);
MODULE_PARM_DESC(writer_range, "Upper bound of writer operating range (default 2*entries)");

struct rcuhashbash_bucket {
	struct hlist_head head;
	union {
		spinlock_t spinlock;
		rwlock_t rwlock;
		struct mutex mutex;
	};
};

struct stats {
	u64 read_hits;
	u64 read_misses;
	u64 write_moves;
	u64 write_dests_in_use;
	u64 write_misses;
};

struct rcuhashbash_ops {
	void (*init_bucket)(struct rcuhashbash_bucket *);
	int (*read)(u32 value, struct stats *stats);
	void (*read_lock_bucket)(struct rcuhashbash_bucket *);
	void (*read_unlock_bucket)(struct rcuhashbash_bucket *);
	int (*write)(u32 src_value, u32 dst_value, struct stats *stats);
	void (*write_lock_buckets)(struct rcuhashbash_bucket *, struct rcuhashbash_bucket *);
	void (*write_unlock_buckets)(struct rcuhashbash_bucket *, struct rcuhashbash_bucket *);
	bool limit_writers;
	int max_writers;
	const char *reader_type;
	const char *writer_type;
};

static struct rcuhashbash_ops *ops;

static DEFINE_SPINLOCK(table_spinlock);
static DEFINE_RWLOCK(table_rwlock);
static DEFINE_MUTEX(table_mutex);
static DEFINE_SEQLOCK(table_seqlock);

static struct rcuhashbash_bucket *hash_table;

struct rcuhashbash_entry {
	struct hlist_node node;
	struct rcu_head rcu_head;
	u32 value;
};

static struct kmem_cache *entry_cache;

static struct task_struct **tasks;

struct stats *thread_stats;

struct rcu_random_state {
	unsigned long rrs_state;
	long rrs_count;
};

#define RCU_RANDOM_MULT 39916801  /* prime */
#define RCU_RANDOM_ADD  479001701 /* prime */
#define RCU_RANDOM_REFRESH 10000

#define DEFINE_RCU_RANDOM(name) struct rcu_random_state name = { 0, 0 }

/*
 * Crude but fast random-number generator.  Uses a linear congruential
 * generator, with occasional help from cpu_clock().
 */
static unsigned long
rcu_random(struct rcu_random_state *rrsp)
{
	if (--rrsp->rrs_count < 0) {
		rrsp->rrs_state +=
			(unsigned long)cpu_clock(raw_smp_processor_id());
		rrsp->rrs_count = RCU_RANDOM_REFRESH;
	}
	rrsp->rrs_state = rrsp->rrs_state * RCU_RANDOM_MULT + RCU_RANDOM_ADD;
	return swahw32(rrsp->rrs_state);
}

static int rcuhashbash_read_nosync(u32 value, struct stats *stats)
{
	struct rcuhashbash_entry *entry;
	struct hlist_node *node;

	hlist_for_each_entry(entry, node, &hash_table[value % buckets].head, node)
		if (entry->value == value)
			break;
	if (node)
		stats->read_hits++;
	else
		stats->read_misses++;

	return 0;
}

static int rcuhashbash_read_nosync_rcu_dereference(u32 value, struct stats *stats)
{
	struct rcuhashbash_entry *entry;
	struct hlist_node *node;

	hlist_for_each_entry_rcu(entry, node, &hash_table[value % buckets].head, node)
		if (entry->value == value)
			break;
	if (node)
		stats->read_hits++;
	else
		stats->read_misses++;

	return 0;
}

static int rcuhashbash_read_rcu(u32 value, struct stats *stats)
{
	struct rcuhashbash_entry *entry;
	struct hlist_node *node;

	rcu_read_lock();
	hlist_for_each_entry_rcu(entry, node, &hash_table[value % buckets].head, node)
		if (entry->value == value)
			break;
	if (node)
		stats->read_hits++;
	else
		stats->read_misses++;
	rcu_read_unlock();

	return 0;
}

static int rcuhashbash_read_lock(u32 value, struct stats *stats)
{
	struct rcuhashbash_entry *entry;
	struct hlist_node *node;
	u32 bucket;

	bucket = value % buckets;

	if (ops->read_lock_bucket)
		ops->read_lock_bucket(&hash_table[bucket]);
	hlist_for_each_entry(entry, node, &hash_table[value % buckets].head, node)
		if (entry->value == value)
			break;
	if (node)
		stats->read_hits++;
	else
		stats->read_misses++;
	if (ops->read_unlock_bucket)
		ops->read_unlock_bucket(&hash_table[bucket]);

	return 0;
}

static int rcuhashbash_read_rcu_seq(u32 value, struct stats *stats)
{
	struct rcuhashbash_entry *entry;
	struct hlist_node *node;
	unsigned long seq;
	bool found;

	do {
		seq = read_seqbegin(&table_seqlock);
		rcu_read_lock();
		hlist_for_each_entry_rcu(entry, node, &hash_table[value % buckets].head, node)
			if (entry->value == value)
				break;
		found = node;
		rcu_read_unlock();
	} while (read_seqretry(&table_seqlock, seq));

	if (found)
		stats->read_hits++;
	else
		stats->read_misses++;

	return 0;
}

static void rcuhashbash_entry_cb(struct rcu_head *rcu_head)
{
	struct rcuhashbash_entry *entry;
	entry = container_of(rcu_head, struct rcuhashbash_entry, rcu_head);
	kmem_cache_free(entry_cache, entry);
}

static int rcuhashbash_write_rcu(u32 src_value, u32 dst_value, struct stats *stats)
{
	int err = 0;
	u32 src_bucket;
	u32 dst_bucket;
	struct rcuhashbash_entry *entry = NULL;
	struct hlist_node *node;
	struct rcuhashbash_entry *src_entry = NULL;
	bool same_bucket;
	bool dest_in_use = false;
	struct rcuhashbash_entry *old_entry = NULL;
	struct hlist_node **src_tail = NULL;
	struct hlist_node **dst_tail = NULL;

	src_bucket = src_value % buckets;
	dst_bucket = dst_value % buckets;
	same_bucket = src_bucket == dst_bucket;

	if (ops->write_lock_buckets)
		ops->write_lock_buckets(&hash_table[src_bucket],
					&hash_table[dst_bucket]);

	/* Find src_tail and src_entry. */
	src_tail = &(hash_table[src_bucket].head.first);
	hlist_for_each_entry(entry, node, &hash_table[src_bucket].head, node) {
		if (entry->value == src_value)
			src_entry = entry;
		if (same_bucket && entry->value == dst_value)
			dest_in_use = true;
		if (!entry->node.next)
			src_tail = &(entry->node.next);
	}
	if (!src_entry) {
		stats->write_misses++;
		goto unlock;
	}
	if (dest_in_use) {
		stats->write_dests_in_use++;
		goto unlock;
	}

	if (same_bucket) {
		src_entry->value = dst_value;
		stats->write_moves++;
		goto unlock;
	}

	/* Find dst_tail and check for existing destination. */
	dst_tail = &(hash_table[dst_bucket].head.first);
	hlist_for_each_entry(entry, node, &hash_table[dst_bucket].head, node) {
		if (entry->value == dst_value) {
			dest_in_use = true;
			break;
		}
		if (!entry->node.next)
			dst_tail = &(entry->node.next);
	}
	if (dest_in_use) {
		stats->write_dests_in_use++;
		goto unlock;
	}

	/* Move the entry to the end of its bucket. */
	if (src_entry->node.next) {
		old_entry = src_entry;
		src_entry = kmem_cache_zalloc(entry_cache, GFP_KERNEL);
		if (!src_entry) {
			err = -ENOMEM;
			goto unlock;
		}
		src_entry->value = old_entry->value;
		src_entry->node.pprev = src_tail;
		smp_wmb(); /* Initialization must appear before insertion */
		*src_tail = &src_entry->node;
		smp_wmb(); /* New entry must appear before old disappears. */
		hlist_del_rcu(&old_entry->node);
		call_rcu(&old_entry->rcu_head, rcuhashbash_entry_cb);
	}

	/* Cross-link and change key to move. */
	*dst_tail = &src_entry->node;
	smp_wmb(); /* Must appear in new bucket before changing key */
	src_entry->value = dst_value;
	smp_wmb(); /* Need new value before removing from old bucket */
	*src_entry->node.pprev = NULL;
	src_entry->node.pprev = dst_tail;

	stats->write_moves++;

unlock:
	if (ops->write_unlock_buckets)
		ops->write_unlock_buckets(&hash_table[src_bucket],
					  &hash_table[dst_bucket]);

	return err;
}

static int rcuhashbash_write_lock(u32 src_value, u32 dst_value, struct stats *stats)
{
	u32 src_bucket;
	u32 dst_bucket;
	struct rcuhashbash_entry *entry = NULL;
	struct hlist_node *node;
	struct rcuhashbash_entry *src_entry = NULL;
	bool same_bucket;
	bool dest_in_use = false;

	src_bucket = src_value % buckets;
	dst_bucket = dst_value % buckets;
	same_bucket = src_bucket == dst_bucket;

	if (ops->write_lock_buckets)
		ops->write_lock_buckets(&hash_table[src_bucket],
					&hash_table[dst_bucket]);

	/* Find src_entry. */
	hlist_for_each_entry(entry, node, &hash_table[src_bucket].head, node) {
		if (entry->value == src_value)
			src_entry = entry;
		if (same_bucket && entry->value == dst_value)
			dest_in_use = true;
	}
	if (!src_entry) {
		stats->write_misses++;
		goto unlock;
	}
	if (dest_in_use) {
		stats->write_dests_in_use++;
		goto unlock;
	}

	if (same_bucket) {
		src_entry->value = dst_value;
		stats->write_moves++;
		goto unlock;
	}

	/* Check for existing destination. */
	hlist_for_each_entry(entry, node, &hash_table[dst_bucket].head, node)
		if (entry->value == dst_value) {
			dest_in_use = true;
			break;
		}
	if (dest_in_use) {
		stats->write_dests_in_use++;
		goto unlock;
	}

	hlist_del(&src_entry->node);
	src_entry->value = dst_value;
	hlist_add_head(&src_entry->node, &hash_table[dst_bucket].head);

	stats->write_moves++;

unlock:
	if (ops->write_unlock_buckets)
		ops->write_unlock_buckets(&hash_table[src_bucket],
					  &hash_table[dst_bucket]);

	return 0;
}

static int rcuhashbash_write_rcu_seq(u32 src_value, u32 dst_value, struct stats *stats)
{
	int err = 0;
	u32 src_bucket;
	u32 dst_bucket;
	struct rcuhashbash_entry *entry = NULL;
	struct hlist_node *node;
	struct rcuhashbash_entry *src_entry = NULL;
	bool same_bucket;
	bool dest_in_use = false;

	src_bucket = src_value % buckets;
	dst_bucket = dst_value % buckets;
	same_bucket = src_bucket == dst_bucket;

	if (ops->write_lock_buckets)
		ops->write_lock_buckets(&hash_table[src_bucket],
					&hash_table[dst_bucket]);

	/* Find src_entry. */
	hlist_for_each_entry(entry, node, &hash_table[src_bucket].head, node) {
		if (entry->value == src_value) {
			src_entry = entry;
			break;
		}
	}
	if (!src_entry) {
		stats->write_misses++;
		goto unlock;
	}

	/* Check for existing destination. */
	hlist_for_each_entry(entry, node, &hash_table[dst_bucket].head, node) {
		if (entry->value == dst_value) {
			dest_in_use = true;
			break;
		}
	}
	if (dest_in_use) {
		stats->write_dests_in_use++;
		goto unlock;
	}

	if (same_bucket) {
		src_entry->value = dst_value;
		stats->write_moves++;
		goto unlock;
	}

	write_seqlock(&table_seqlock);
	hlist_del_rcu(&src_entry->node);
	hlist_add_head_rcu(&src_entry->node, &hash_table[dst_bucket].head);
	src_entry->value = dst_value;
	write_sequnlock(&table_seqlock);

	stats->write_moves++;

unlock:
	if (ops->write_unlock_buckets)
		ops->write_unlock_buckets(&hash_table[src_bucket],
					  &hash_table[dst_bucket]);

	return err;
}

static int rcuhashbash_ro_thread(void *arg)
{
	int err;
	struct stats *stats_ret = arg;
	struct stats stats = {};
	DEFINE_RCU_RANDOM(rand);

	set_user_nice(current, 19);

	do {
		cond_resched();
		err = ops->read(rcu_random(&rand) % reader_range, &stats);
	} while (!kthread_should_stop() && !err);

	*stats_ret = stats;

	while (!kthread_should_stop())
		schedule_timeout_interruptible(1);
	return err;
}

static int rcuhashbash_rw_thread(void *arg)
{
	int err;
	struct stats *stats_ret = arg;
	struct stats stats = {};
	DEFINE_RCU_RANDOM(rand);

	set_user_nice(current, 19);

	do {
		cond_resched();
		if ((rcu_random(&rand) % rw_total) < rw_writes)
			err = ops->write(rcu_random(&rand) % writer_range,
			                 rcu_random(&rand) % writer_range,
			                 &stats);
		else
			err = ops->read(rcu_random(&rand) % reader_range,
			                &stats);
	} while (!kthread_should_stop() && !err);

	*stats_ret = stats;

	while (!kthread_should_stop())
		schedule_timeout_interruptible(1);
	return err;
}

static void spinlock_init_bucket(struct rcuhashbash_bucket *bucket)
{
	spin_lock_init(&bucket->spinlock);
}

static void rwlock_init_bucket(struct rcuhashbash_bucket *bucket)
{
	rwlock_init(&bucket->rwlock);
}

static void mutex_init_bucket(struct rcuhashbash_bucket *bucket)
{
	mutex_init(&bucket->mutex);
}

static void spinlock_read_lock_bucket(struct rcuhashbash_bucket *bucket)
{
	spin_lock(&bucket->spinlock);
}

static void rwlock_read_lock_bucket(struct rcuhashbash_bucket *bucket)
{
	read_lock(&bucket->rwlock);
}

static void mutex_read_lock_bucket(struct rcuhashbash_bucket *bucket)
{
	mutex_lock(&bucket->mutex);
}

static void table_spinlock_read_lock_bucket(struct rcuhashbash_bucket *bucket)
{
	spin_lock(&table_spinlock);
}

static void table_rwlock_read_lock_bucket(struct rcuhashbash_bucket *bucket)
{
	read_lock(&table_rwlock);
}

static void table_mutex_read_lock_bucket(struct rcuhashbash_bucket *bucket)
{
	mutex_lock(&table_mutex);
}

static void spinlock_read_unlock_bucket(struct rcuhashbash_bucket *bucket)
{
	spin_unlock(&bucket->spinlock);
}

static void rwlock_read_unlock_bucket(struct rcuhashbash_bucket *bucket)
{
	read_unlock(&bucket->rwlock);
}

static void mutex_read_unlock_bucket(struct rcuhashbash_bucket *bucket)
{
	mutex_unlock(&bucket->mutex);
}

static void table_spinlock_read_unlock_bucket(struct rcuhashbash_bucket *bucket)
{
	spin_unlock(&table_spinlock);
}

static void table_rwlock_read_unlock_bucket(struct rcuhashbash_bucket *bucket)
{
	read_unlock(&table_rwlock);
}

static void table_mutex_read_unlock_bucket(struct rcuhashbash_bucket *bucket)
{
	mutex_unlock(&table_mutex);
}

static void spinlock_write_lock_buckets(struct rcuhashbash_bucket *b1,
                                        struct rcuhashbash_bucket *b2)
{
	if (b1 == b2)
		spin_lock(&b1->spinlock);
	else if (b1 < b2) {
		spin_lock(&b1->spinlock);
		spin_lock_nested(&b2->spinlock, SINGLE_DEPTH_NESTING);
	} else {
		spin_lock(&b2->spinlock);
		spin_lock_nested(&b1->spinlock, SINGLE_DEPTH_NESTING);
	}
}

static void rwlock_write_lock_buckets(struct rcuhashbash_bucket *b1,
                                      struct rcuhashbash_bucket *b2)
{
	if (b1 == b2)
		write_lock(&b1->rwlock);
	else if (b1 < b2) {
		write_lock(&b1->rwlock);
		write_lock(&b2->rwlock);
	} else {
		write_lock(&b2->rwlock);
		write_lock(&b1->rwlock);
	}
}

static void mutex_write_lock_buckets(struct rcuhashbash_bucket *b1,
                                     struct rcuhashbash_bucket *b2)
{
	if (b1 == b2)
		mutex_lock(&b1->mutex);
	else if (b1 < b2) {
		mutex_lock(&b1->mutex);
		mutex_lock_nested(&b2->mutex, SINGLE_DEPTH_NESTING);
	} else {
		mutex_lock(&b2->mutex);
		mutex_lock_nested(&b1->mutex, SINGLE_DEPTH_NESTING);
	}
}

static void table_spinlock_write_lock_buckets(struct rcuhashbash_bucket *b1,
                                              struct rcuhashbash_bucket *b2)
{
	spin_lock(&table_spinlock);
}

static void table_rwlock_write_lock_buckets(struct rcuhashbash_bucket *b1,
                                            struct rcuhashbash_bucket *b2)
{
	write_lock(&table_rwlock);
}

static void table_mutex_write_lock_buckets(struct rcuhashbash_bucket *b1,
                                           struct rcuhashbash_bucket *b2)
{
	mutex_lock(&table_mutex);
}

static void spinlock_write_unlock_buckets(struct rcuhashbash_bucket *b1,
                                          struct rcuhashbash_bucket *b2)
{
	spin_unlock(&b1->spinlock);
	if (b1 != b2)
		spin_unlock(&b2->spinlock);
}

static void rwlock_write_unlock_buckets(struct rcuhashbash_bucket *b1,
                                        struct rcuhashbash_bucket *b2)
{
	write_unlock(&b1->rwlock);
	if (b1 != b2)
		write_unlock(&b2->rwlock);
}

static void mutex_write_unlock_buckets(struct rcuhashbash_bucket *b1,
                                       struct rcuhashbash_bucket *b2)
{
	mutex_unlock(&b1->mutex);
	if (b1 != b2)
		mutex_unlock(&b2->mutex);
}

static void table_spinlock_write_unlock_buckets(struct rcuhashbash_bucket *b1,
                                                struct rcuhashbash_bucket *b2)
{
	spin_unlock(&table_spinlock);
}

static void table_rwlock_write_unlock_buckets(struct rcuhashbash_bucket *b1,
                                              struct rcuhashbash_bucket *b2)
{
	write_unlock(&table_rwlock);
}

static void table_mutex_write_unlock_buckets(struct rcuhashbash_bucket *b1,
                                             struct rcuhashbash_bucket *b2)
{
	mutex_unlock(&table_mutex);
}

static struct rcuhashbash_ops all_ops[] = {
	{
		.reader_type = "nosync",
		.writer_type = "none",
		.read = rcuhashbash_read_nosync,
		.write = NULL,
		.limit_writers = true,
		.max_writers = 0,
	},
	{
		.reader_type = "nosync_rcu_dereference",
		.writer_type = "none",
		.read = rcuhashbash_read_nosync_rcu_dereference,
		.write = NULL,
		.limit_writers = true,
		.max_writers = 0,
	},
	{
		.reader_type = "rcu",
		.writer_type = "single",
		.read = rcuhashbash_read_rcu,
		.write = rcuhashbash_write_rcu,
		.limit_writers = true,
		.max_writers = 1,
	},
	{
		.reader_type = "rcu",
		.writer_type = "spinlock",
		.init_bucket = spinlock_init_bucket,
		.read = rcuhashbash_read_rcu,
		.write = rcuhashbash_write_rcu,
		.write_lock_buckets = spinlock_write_lock_buckets,
		.write_unlock_buckets = spinlock_write_unlock_buckets,
	},
	{
		.reader_type = "rcu",
		.writer_type = "rwlock",
		.init_bucket = rwlock_init_bucket,
		.read = rcuhashbash_read_rcu,
		.write = rcuhashbash_write_rcu,
		.write_lock_buckets = rwlock_write_lock_buckets,
		.write_unlock_buckets = rwlock_write_unlock_buckets,
	},
	{
		.reader_type = "rcu",
		.writer_type = "mutex",
		.init_bucket = mutex_init_bucket,
		.read = rcuhashbash_read_rcu,
		.write = rcuhashbash_write_rcu,
		.write_lock_buckets = mutex_write_lock_buckets,
		.write_unlock_buckets = mutex_write_unlock_buckets,
	},
	{
		.reader_type = "rcu",
		.writer_type = "table_spinlock",
		.read = rcuhashbash_read_rcu,
		.write = rcuhashbash_write_rcu,
		.write_lock_buckets = table_spinlock_write_lock_buckets,
		.write_unlock_buckets = table_spinlock_write_unlock_buckets,
	},
	{
		.reader_type = "rcu",
		.writer_type = "table_rwlock",
		.read = rcuhashbash_read_rcu,
		.write = rcuhashbash_write_rcu,
		.write_lock_buckets = table_rwlock_write_lock_buckets,
		.write_unlock_buckets = table_rwlock_write_unlock_buckets,
	},
	{
		.reader_type = "rcu",
		.writer_type = "table_mutex",
		.read = rcuhashbash_read_rcu,
		.write = rcuhashbash_write_rcu,
		.write_lock_buckets = table_mutex_write_lock_buckets,
		.write_unlock_buckets = table_mutex_write_unlock_buckets,
	},
	{
		.reader_type = "rcu_seq",
		.writer_type = "single",
		.read = rcuhashbash_read_rcu_seq,
		.write = rcuhashbash_write_rcu_seq,
		.limit_writers = true,
		.max_writers = 1,
	},
	{
		.reader_type = "rcu_seq",
		.writer_type = "spinlock",
		.init_bucket = spinlock_init_bucket,
		.read = rcuhashbash_read_rcu_seq,
		.write = rcuhashbash_write_rcu_seq,
		.write_lock_buckets = spinlock_write_lock_buckets,
		.write_unlock_buckets = spinlock_write_unlock_buckets,
	},
	{
		.reader_type = "rcu_seq",
		.writer_type = "rwlock",
		.init_bucket = rwlock_init_bucket,
		.read = rcuhashbash_read_rcu_seq,
		.write = rcuhashbash_write_rcu_seq,
		.write_lock_buckets = rwlock_write_lock_buckets,
		.write_unlock_buckets = rwlock_write_unlock_buckets,
	},
	{
		.reader_type = "rcu_seq",
		.writer_type = "mutex",
		.init_bucket = mutex_init_bucket,
		.read = rcuhashbash_read_rcu_seq,
		.write = rcuhashbash_write_rcu_seq,
		.write_lock_buckets = mutex_write_lock_buckets,
		.write_unlock_buckets = mutex_write_unlock_buckets,
	},
	{
		.reader_type = "rcu_seq",
		.writer_type = "table_spinlock",
		.read = rcuhashbash_read_rcu_seq,
		.write = rcuhashbash_write_rcu_seq,
		.write_lock_buckets = table_spinlock_write_lock_buckets,
		.write_unlock_buckets = table_spinlock_write_unlock_buckets,
	},
	{
		.reader_type = "rcu_seq",
		.writer_type = "table_rwlock",
		.read = rcuhashbash_read_rcu_seq,
		.write = rcuhashbash_write_rcu_seq,
		.write_lock_buckets = table_rwlock_write_lock_buckets,
		.write_unlock_buckets = table_rwlock_write_unlock_buckets,
	},
	{
		.reader_type = "rcu_seq",
		.writer_type = "table_mutex",
		.read = rcuhashbash_read_rcu_seq,
		.write = rcuhashbash_write_rcu_seq,
		.write_lock_buckets = table_mutex_write_lock_buckets,
		.write_unlock_buckets = table_mutex_write_unlock_buckets,
	},
	{
		.reader_type = "spinlock",
		.writer_type = "spinlock",
		.init_bucket = spinlock_init_bucket,
		.read = rcuhashbash_read_lock,
		.read_lock_bucket = spinlock_read_lock_bucket,
		.read_unlock_bucket = spinlock_read_unlock_bucket,
		.write = rcuhashbash_write_lock,
		.write_lock_buckets = spinlock_write_lock_buckets,
		.write_unlock_buckets = spinlock_write_unlock_buckets,
	},
	{
		.reader_type = "rwlock",
		.writer_type = "rwlock",
		.init_bucket = rwlock_init_bucket,
		.read = rcuhashbash_read_lock,
		.read_lock_bucket = rwlock_read_lock_bucket,
		.read_unlock_bucket = rwlock_read_unlock_bucket,
		.write = rcuhashbash_write_lock,
		.write_lock_buckets = rwlock_write_lock_buckets,
		.write_unlock_buckets = rwlock_write_unlock_buckets,
	},
	{
		.reader_type = "mutex",
		.writer_type = "mutex",
		.init_bucket = mutex_init_bucket,
		.read = rcuhashbash_read_lock,
		.read_lock_bucket = mutex_read_lock_bucket,
		.read_unlock_bucket = mutex_read_unlock_bucket,
		.write = rcuhashbash_write_lock,
		.write_lock_buckets = mutex_write_lock_buckets,
		.write_unlock_buckets = mutex_write_unlock_buckets,
	},
	{
		.reader_type = "table_spinlock",
		.writer_type = "table_spinlock",
		.read = rcuhashbash_read_lock,
		.read_lock_bucket = table_spinlock_read_lock_bucket,
		.read_unlock_bucket = table_spinlock_read_unlock_bucket,
		.write = rcuhashbash_write_lock,
		.write_lock_buckets = table_spinlock_write_lock_buckets,
		.write_unlock_buckets = table_spinlock_write_unlock_buckets,
	},
	{
		.reader_type = "table_rwlock",
		.writer_type = "table_rwlock",
		.read = rcuhashbash_read_lock,
		.read_lock_bucket = table_rwlock_read_lock_bucket,
		.read_unlock_bucket = table_rwlock_read_unlock_bucket,
		.write = rcuhashbash_write_lock,
		.write_lock_buckets = table_rwlock_write_lock_buckets,
		.write_unlock_buckets = table_rwlock_write_unlock_buckets,
	},
	{
		.reader_type = "table_mutex",
		.writer_type = "table_mutex",
		.read = rcuhashbash_read_lock,
		.read_lock_bucket = table_mutex_read_lock_bucket,
		.read_unlock_bucket = table_mutex_read_unlock_bucket,
		.write = rcuhashbash_write_lock,
		.write_lock_buckets = table_mutex_write_lock_buckets,
		.write_unlock_buckets = table_mutex_write_unlock_buckets,
	},
};

static struct rcuhashbash_ops *ops;

static void rcuhashbash_print_stats(void)
{
	int i;
	struct stats s = {};

	if (!thread_stats) {
		printk(KERN_ALERT "rcuhashbash stats unavailable\n");
		return;
	}

	for (i = 0; i < ro + rw; i++) {
		s.read_hits += thread_stats[i].read_hits;
		s.read_misses += thread_stats[i].read_misses;
		s.write_moves += thread_stats[i].write_moves;
		s.write_dests_in_use += thread_stats[i].write_dests_in_use;
		s.write_misses += thread_stats[i].write_misses;
	}

	printk(KERN_ALERT "rcuhashbash summary: ro=%d rw=%d reader_type=%s writer_type=%s\n"
	       KERN_ALERT "rcuhashbash summary: writer proportion %lu/%lu\n"
	       KERN_ALERT "rcuhashbash summary: buckets=%lu entries=%lu reader_range=%lu writer_range=%lu\n"
	       KERN_ALERT "rcuhashbash summary: writes: %llu moves, %llu dests in use, %llu misses\n"
	       KERN_ALERT "rcuhashbash summary: reads: %llu hits, %llu misses\n",
	       ro, rw, reader_type, writer_type,
	       rw_writes, rw_total,
	       buckets, entries, reader_range, writer_range,
	       s.write_moves, s.write_dests_in_use, s.write_misses,
	       s.read_hits, s.read_misses);
}

static void rcuhashbash_exit(void)
{
	unsigned long i;
	int ret;

	if (tasks) {
		for (i = 0; i < ro + rw; i++)
			if (tasks[i]) {
				ret = kthread_stop(tasks[i]);
				if(ret)
					printk(KERN_ALERT "rcuhashbash task returned error %d\n", ret);
			}
		kfree(tasks);
	}

	/* Wait for all RCU callbacks to complete. */
	rcu_barrier();

	if (hash_table) {
		for (i = 0; i < buckets; i++) {
			struct hlist_head *head = &hash_table[i].head;
			while (!hlist_empty(head)) {
				struct rcuhashbash_entry *entry;
				entry = hlist_entry(head->first, struct rcuhashbash_entry, node);
				hlist_del(head->first);
				kmem_cache_free(entry_cache, entry);
			}
		}
		kfree(hash_table);
	}

	if (entry_cache)
		kmem_cache_destroy(entry_cache);

	rcuhashbash_print_stats();

	kfree(thread_stats);

	printk(KERN_ALERT "rcuhashbash done\n");
}

static __init int rcuhashbash_init(void)
{
	int ret;
	u32 i;

	for (i = 0; i < ARRAY_SIZE(all_ops); i++)
		if (strcmp(reader_type, all_ops[i].reader_type) == 0
		    && strcmp(writer_type, all_ops[i].writer_type) == 0) {
			ops = &all_ops[i];
		}
	if (!ops) {
		printk(KERN_ALERT "rcuhashbash: No implementation with %s reader and %s writer\n",
		       reader_type, writer_type);
		return -EINVAL;
	}

	if (rw < 0)
		rw = num_online_cpus();
	if (ops->limit_writers && rw > ops->max_writers) {
		printk(KERN_ALERT "rcuhashbash: %s writer implementation supports at most %d writers\n",
		       writer_type, ops->max_writers);
		return -EINVAL;
	}

	if (!ops->read) {
		printk(KERN_ALERT "rcuhashbash: Internal error: read function NULL\n");
		return -EINVAL;
	}
	if (rw > 0 && !ops->write) {
		printk(KERN_ALERT "rcuhashbash: Internal error: rw > 0 but write function NULL\n");
		return -EINVAL;
	}

	if (reader_range == 0)
		reader_range = 2*entries;
	if (writer_range == 0)
		writer_range = 2*entries;

	entry_cache = KMEM_CACHE(rcuhashbash_entry, 0);
	if (!entry_cache)
		goto enomem;

	hash_table = kcalloc(buckets, sizeof(hash_table[0]), GFP_KERNEL);
	if (!hash_table)
		goto enomem;

	if (ops->init_bucket)
		for (i = 0; i < buckets; i++)
			ops->init_bucket(&hash_table[i]);

	for (i = 0; i < entries; i++) {
		struct rcuhashbash_entry *entry;
		entry = kmem_cache_zalloc(entry_cache, GFP_KERNEL);
		if(!entry)
			goto enomem;
		entry->value = i;
		hlist_add_head(&entry->node, &hash_table[entry->value % buckets].head);
	}

	thread_stats = kcalloc(rw + ro, sizeof(thread_stats[0]), GFP_KERNEL);
	if (!thread_stats)
		goto enomem;

	tasks = kcalloc(rw + ro, sizeof(tasks[0]), GFP_KERNEL);
	if (!tasks)
		goto enomem;

	printk(KERN_ALERT "rcuhashbash starting threads\n");

	for (i = 0; i < ro + rw; i++) {
		struct task_struct *task;
		if (i < ro)
			task = kthread_run(rcuhashbash_ro_thread,
			                   &thread_stats[i],
			                   "rcuhashbash_ro");
		else
			task = kthread_run(rcuhashbash_rw_thread,
			                   &thread_stats[i],
			                   "rcuhashbash_rw");
		if (IS_ERR(task)) {
			ret = PTR_ERR(task);
			goto error;
		}
		tasks[i] = task;
	}

	return 0;

enomem:
	ret = -ENOMEM;
error:
	rcuhashbash_exit();
	return ret;
}

module_init(rcuhashbash_init);
module_exit(rcuhashbash_exit);
