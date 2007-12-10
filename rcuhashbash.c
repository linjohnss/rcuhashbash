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
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/string.h>

MODULE_AUTHOR("Josh Triplett <josh@kernel.org>");
MODULE_DESCRIPTION("RCU hash algorithm test module.");
MODULE_LICENSE("GPL");

static char *reader_type = "rcu"; /* Reader implementation to benchmark */
static char *writer_type = "spinlock"; /* Writer implementation to benchmark */
static int readers = -1; /* Number of reader tasks; defaults to online CPUs */
static int writers = -1; /* Number of writer tasks; defaults to online CPUs */
static unsigned long buckets = 1024; /* Number of hash table buckets */
static unsigned long entries = 4096; /* Number of entries initially added */

module_param(reader_type, charp, 0444);
MODULE_PARM_DESC(reader_type, "Hash table reader implementation");
module_param(writer_type, charp, 0444);
MODULE_PARM_DESC(writer_type, "Hash table writer implementation");
module_param(readers, int, 0444);
MODULE_PARM_DESC(readers, "Number of reader threads");
module_param(writers, int, 0444);
MODULE_PARM_DESC(writers, "Number of writer threads");
module_param(buckets, ulong, 0444);
MODULE_PARM_DESC(buckets, "Number of hash buckets");
module_param(entries, ulong, 0444);
MODULE_PARM_DESC(entries, "Number of hash table entries");

struct rcuhashbash_bucket {
	struct hlist_head head;
	union {
		spinlock_t spinlock;
		rwlock_t rwlock;
		struct mutex mutex;
	};
};

struct rcuhashbash_ops {
	void (*init_bucket)(struct rcuhashbash_bucket *);
	int (*reader_thread)(void *);
	void (*read_lock_bucket)(struct rcuhashbash_bucket *);
	void (*read_unlock_bucket)(struct rcuhashbash_bucket *);
	int (*writer_thread)(void *);
	void (*write_lock_buckets)(struct rcuhashbash_bucket *, struct rcuhashbash_bucket *);
	void (*write_unlock_buckets)(struct rcuhashbash_bucket *, struct rcuhashbash_bucket *);
	int max_writers;
	const char *reader_type;
	const char *writer_type;
};

static struct rcuhashbash_ops *ops;

static DEFINE_SPINLOCK(table_spinlock);
static DEFINE_RWLOCK(table_rwlock);
static DEFINE_MUTEX(table_mutex);

static struct rcuhashbash_bucket *hash_table;

struct rcuhashbash_entry {
	struct hlist_node node;
	struct rcu_head rcu_head;
	u32 value;
};

static struct kmem_cache *entry_cache;

static struct task_struct **reader_tasks;
static struct task_struct **writer_tasks;

struct reader_stats {
	u64 hits;
	u64 misses;
} ____cacheline_aligned_in_smp;

struct writer_stats {
	u64 moves;
	u64 dests_in_use;
	u64 misses;
} ____cacheline_aligned_in_smp;

struct reader_stats *reader_stats;
struct writer_stats *writer_stats;

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

static int rcuhashbash_reader_rcu(void *arg)
{
	struct reader_stats *stats = arg;
	DEFINE_RCU_RANDOM(rand);

	set_user_nice(current, 19);

	do {
		struct rcuhashbash_entry *entry;
		struct hlist_node *node;
		u32 value;

		cond_resched();

		value = rcu_random(&rand) % (entries * 2);

		rcu_read_lock();
		hlist_for_each_entry_rcu(entry, node, &hash_table[value % buckets].head, node)
			if (entry->value == value)
				break;
		if (node)
			stats->hits++;
		else
			stats->misses++;
		rcu_read_unlock();
	} while (!kthread_should_stop());

	return 0;
}

static int rcuhashbash_reader_lock(void *arg)
{
	struct reader_stats *stats = arg;
	DEFINE_RCU_RANDOM(rand);

	set_user_nice(current, 19);

	do {
		struct rcuhashbash_entry *entry;
		struct hlist_node *node;
		u32 value, bucket;

		cond_resched();

		value = rcu_random(&rand) % (entries * 2);
		bucket = value % buckets;

		if (ops->read_lock_bucket)
			ops->read_lock_bucket(&hash_table[bucket]);
		hlist_for_each_entry(entry, node, &hash_table[value % buckets].head, node)
			if (entry->value == value)
				break;
		if (node)
			stats->hits++;
		else
			stats->misses++;
		if (ops->read_unlock_bucket)
			ops->read_unlock_bucket(&hash_table[bucket]);
	} while (!kthread_should_stop());

	return 0;
}

static void rcuhashbash_entry_cb(struct rcu_head *rcu_head)
{
	struct rcuhashbash_entry *entry;
	entry = container_of(rcu_head, struct rcuhashbash_entry, rcu_head);
	kmem_cache_free(entry_cache, entry);
}

static int rcuhashbash_writer_rcu(void *arg)
{
	int err = 0;
	struct writer_stats *stats = arg;
	DEFINE_RCU_RANDOM(rand);

	set_user_nice(current, 19);

	do {
		u32 src_value, src_bucket;
		u32 dst_value, dst_bucket;
		struct rcuhashbash_entry *entry = NULL;
		struct hlist_node *node;
		struct rcuhashbash_entry *src_entry = NULL;
		bool same_bucket;
		bool dest_in_use = false;
		struct rcuhashbash_entry *old_entry = NULL;
		struct hlist_node **src_tail = NULL;
		struct hlist_node **dst_tail = NULL;

		cond_resched();

		src_value = rcu_random(&rand) % (entries * 2);
		src_bucket = src_value % buckets;
		dst_value = rcu_random(&rand) % (entries * 2);
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
			stats->misses++;
			goto unlock_and_loop;
		}
		if (dest_in_use) {
			stats->dests_in_use++;
			goto unlock_and_loop;
		}

		if (same_bucket) {
			src_entry->value = dst_value;
			stats->moves++;
			goto unlock_and_loop;
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
			stats->dests_in_use++;
			goto unlock_and_loop;
		}

		/* Move the entry to the end of its bucket. */
		if (src_entry->node.next) {
			old_entry = src_entry;
			src_entry = kmem_cache_zalloc(entry_cache, GFP_KERNEL);
			if (!src_entry) {
				err = -ENOMEM;
				goto unlock_and_loop;
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

		stats->moves++;

unlock_and_loop:
		if (ops->write_unlock_buckets)
			ops->write_unlock_buckets(&hash_table[src_bucket],
			                          &hash_table[dst_bucket]);
	} while (!kthread_should_stop() && !err);

	while (!kthread_should_stop())
		schedule_timeout_interruptible(1);
	return err;
}

static int rcuhashbash_writer_lock(void *arg)
{
	struct writer_stats *stats = arg;
	DEFINE_RCU_RANDOM(rand);

	set_user_nice(current, 19);

	do {
		u32 src_value, src_bucket;
		u32 dst_value, dst_bucket;
		struct rcuhashbash_entry *entry = NULL;
		struct hlist_node *node;
		struct rcuhashbash_entry *src_entry = NULL;
		bool same_bucket;
		bool dest_in_use = false;

		cond_resched();

		src_value = rcu_random(&rand) % (entries * 2);
		src_bucket = src_value % buckets;
		dst_value = rcu_random(&rand) % (entries * 2);
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
			stats->misses++;
			goto unlock_and_loop;
		}
		if (dest_in_use) {
			stats->dests_in_use++;
			goto unlock_and_loop;
		}

		if (same_bucket) {
			src_entry->value = dst_value;
			stats->moves++;
			goto unlock_and_loop;
		}

		/* Check for existing destination. */
		hlist_for_each_entry(entry, node, &hash_table[dst_bucket].head, node)
			if (entry->value == dst_value) {
				dest_in_use = true;
				break;
			}
		if (dest_in_use) {
			stats->dests_in_use++;
			goto unlock_and_loop;
		}

		hlist_del(&src_entry->node);
		src_entry->value = dst_value;
		hlist_add_head(&src_entry->node, &hash_table[dst_bucket].head);

		stats->moves++;

unlock_and_loop:
		if (ops->write_unlock_buckets)
			ops->write_unlock_buckets(&hash_table[src_bucket],
			                          &hash_table[dst_bucket]);
	} while (!kthread_should_stop());

	return 0;
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
		.reader_type = "rcu",
		.writer_type = "single",
		.reader_thread = rcuhashbash_reader_rcu,
		.writer_thread = rcuhashbash_writer_rcu,
		.max_writers = 1,
	},
	{
		.reader_type = "rcu",
		.writer_type = "spinlock",
		.init_bucket = spinlock_init_bucket,
		.reader_thread = rcuhashbash_reader_rcu,
		.writer_thread = rcuhashbash_writer_rcu,
		.write_lock_buckets = spinlock_write_lock_buckets,
		.write_unlock_buckets = spinlock_write_unlock_buckets,
	},
	{
		.reader_type = "rcu",
		.writer_type = "rwlock",
		.init_bucket = rwlock_init_bucket,
		.reader_thread = rcuhashbash_reader_rcu,
		.writer_thread = rcuhashbash_writer_rcu,
		.write_lock_buckets = rwlock_write_lock_buckets,
		.write_unlock_buckets = rwlock_write_unlock_buckets,
	},
	{
		.reader_type = "rcu",
		.writer_type = "mutex",
		.init_bucket = mutex_init_bucket,
		.reader_thread = rcuhashbash_reader_rcu,
		.writer_thread = rcuhashbash_writer_rcu,
		.write_lock_buckets = mutex_write_lock_buckets,
		.write_unlock_buckets = mutex_write_unlock_buckets,
	},
	{
		.reader_type = "rcu",
		.writer_type = "table_spinlock",
		.reader_thread = rcuhashbash_reader_rcu,
		.writer_thread = rcuhashbash_writer_rcu,
		.write_lock_buckets = table_spinlock_write_lock_buckets,
		.write_unlock_buckets = table_spinlock_write_unlock_buckets,
	},
	{
		.reader_type = "rcu",
		.writer_type = "table_rwlock",
		.reader_thread = rcuhashbash_reader_rcu,
		.writer_thread = rcuhashbash_writer_rcu,
		.write_lock_buckets = table_rwlock_write_lock_buckets,
		.write_unlock_buckets = table_rwlock_write_unlock_buckets,
	},
	{
		.reader_type = "rcu",
		.writer_type = "table_mutex",
		.reader_thread = rcuhashbash_reader_rcu,
		.writer_thread = rcuhashbash_writer_rcu,
		.write_lock_buckets = table_mutex_write_lock_buckets,
		.write_unlock_buckets = table_mutex_write_unlock_buckets,
	},
	{
		.reader_type = "spinlock",
		.writer_type = "spinlock",
		.init_bucket = spinlock_init_bucket,
		.reader_thread = rcuhashbash_reader_lock,
		.read_lock_bucket = spinlock_read_lock_bucket,
		.read_unlock_bucket = spinlock_read_unlock_bucket,
		.writer_thread = rcuhashbash_writer_lock,
		.write_lock_buckets = spinlock_write_lock_buckets,
		.write_unlock_buckets = spinlock_write_unlock_buckets,
	},
	{
		.reader_type = "rwlock",
		.writer_type = "rwlock",
		.init_bucket = rwlock_init_bucket,
		.reader_thread = rcuhashbash_reader_lock,
		.read_lock_bucket = rwlock_read_lock_bucket,
		.read_unlock_bucket = rwlock_read_unlock_bucket,
		.writer_thread = rcuhashbash_writer_lock,
		.write_lock_buckets = rwlock_write_lock_buckets,
		.write_unlock_buckets = rwlock_write_unlock_buckets,
	},
	{
		.reader_type = "mutex",
		.writer_type = "mutex",
		.init_bucket = mutex_init_bucket,
		.reader_thread = rcuhashbash_reader_lock,
		.read_lock_bucket = mutex_read_lock_bucket,
		.read_unlock_bucket = mutex_read_unlock_bucket,
		.writer_thread = rcuhashbash_writer_lock,
		.write_lock_buckets = mutex_write_lock_buckets,
		.write_unlock_buckets = mutex_write_unlock_buckets,
	},
	{
		.reader_type = "table_spinlock",
		.writer_type = "table_spinlock",
		.reader_thread = rcuhashbash_reader_lock,
		.read_lock_bucket = table_spinlock_read_lock_bucket,
		.read_unlock_bucket = table_spinlock_read_unlock_bucket,
		.writer_thread = rcuhashbash_writer_lock,
		.write_lock_buckets = table_spinlock_write_lock_buckets,
		.write_unlock_buckets = table_spinlock_write_unlock_buckets,
	},
	{
		.reader_type = "table_rwlock",
		.writer_type = "table_rwlock",
		.reader_thread = rcuhashbash_reader_lock,
		.read_lock_bucket = table_rwlock_read_lock_bucket,
		.read_unlock_bucket = table_rwlock_read_unlock_bucket,
		.writer_thread = rcuhashbash_writer_lock,
		.write_lock_buckets = table_rwlock_write_lock_buckets,
		.write_unlock_buckets = table_rwlock_write_unlock_buckets,
	},
	{
		.reader_type = "table_mutex",
		.writer_type = "table_mutex",
		.reader_thread = rcuhashbash_reader_lock,
		.read_lock_bucket = table_mutex_read_lock_bucket,
		.read_unlock_bucket = table_mutex_read_unlock_bucket,
		.writer_thread = rcuhashbash_writer_lock,
		.write_lock_buckets = table_mutex_write_lock_buckets,
		.write_unlock_buckets = table_mutex_write_unlock_buckets,
	},
};

static struct rcuhashbash_ops *ops;

static void rcuhashbash_print_stats(void)
{
	int i;
	struct reader_stats rs = { 0 };
	struct writer_stats ws = { 0 };

	if (!reader_stats) {
		printk(KERN_ALERT "rcuhashbash stats unavailable\n");
		return;
	}

	for (i = 0; i < readers; i++) {
		rs.hits += reader_stats[i].hits;
		rs.misses += reader_stats[i].misses;
	}

	for (i = 0; i < writers; i++) {
		ws.moves += writer_stats[i].moves;
		ws.dests_in_use += writer_stats[i].dests_in_use;
		ws.misses += writer_stats[i].misses;
	}

	printk(KERN_ALERT "rcuhashbash summary: readers=%d reader_type=%s writers=%d writer_type=%s\n"
	       KERN_ALERT "rcuhashbash summary: buckets=%lu entries=%lu\n"
	       KERN_ALERT "rcuhashbash summary: writers: %llu moves, %llu dests in use, %llu misses\n"
	       KERN_ALERT "rcuhashbash summary: readers: %llu hits, %llu misses\n",
	       readers, reader_type, writers, writer_type,
	       buckets, entries,
	       ws.moves, ws.dests_in_use, ws.misses,
	       rs.hits, rs.misses);
}

static void rcuhashbash_exit(void)
{
	unsigned long i;
	int ret;

	if (writer_tasks) {
		for (i = 0; i < writers; i++)
			if (writer_tasks[i]) {
				ret = kthread_stop(writer_tasks[i]);
				if(ret)
					printk(KERN_ALERT "rcuhashbash writer returned error %d\n", ret);
			}
		kfree(writer_tasks);
	}

	if (reader_tasks) {
		for (i = 0; i < readers; i++)
			if (reader_tasks[i]) {
				ret = kthread_stop(reader_tasks[i]);
				if(ret)
					printk(KERN_ALERT "rcuhashbash reader returned error %d\n", ret);
			}
		kfree(reader_tasks);
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

	kfree(writer_stats);
	kfree(reader_stats);

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
	if (!ops->reader_thread || !ops->writer_thread) {
		printk(KERN_ALERT "rcuhashbash: Internal error: reader or writer thread NULL\n");
		return -EINVAL;
	}

	if (readers < 0)
		readers = num_online_cpus();
	if (writers < 0)
		writers = num_online_cpus();
	if (ops->max_writers && writers > ops->max_writers) {
		printk(KERN_ALERT "rcuhashbash: %s writer implementation supports at most %d writers\n",
		       writer_type, ops->max_writers);
		return -EINVAL;
	}

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

	reader_stats = kcalloc(readers, sizeof(reader_stats[0]), GFP_KERNEL);
	if (!reader_stats)
		goto enomem;

	reader_tasks = kcalloc(readers, sizeof(reader_tasks[0]), GFP_KERNEL);
	if (!reader_tasks)
		goto enomem;

	writer_stats = kcalloc(writers, sizeof(writer_stats[0]), GFP_KERNEL);
	if (!writer_stats)
		goto enomem;

	writer_tasks = kcalloc(writers, sizeof(writer_tasks[0]), GFP_KERNEL);
	if (!writer_tasks)
		goto enomem;

	printk(KERN_ALERT "rcuhashbash starting threads\n");

	for (i = 0; i < readers; i++) {
		struct task_struct *task;
		task = kthread_run(ops->reader_thread, &reader_stats[i],
		                   "rcuhashbash_reader");
		if (IS_ERR(task)) {
			ret = PTR_ERR(task);
			goto error;
		}
		reader_tasks[i] = task;
	}

	for (i = 0; i < writers; i++) {
		struct task_struct *task;
		task = kthread_run(ops->writer_thread, &writer_stats[i],
		                   "rcuhashbash_writer");
		if (IS_ERR(task)) {
			ret = PTR_ERR(task);
			goto error;
		}
		writer_tasks[i] = task;
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
