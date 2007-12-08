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
#include <linux/random.h>
#include <linux/rcupdate.h>
#include <linux/slab.h>
#include <linux/spinlock.h>

MODULE_AUTHOR("Josh Triplett <josh@kernel.org>");
MODULE_DESCRIPTION("RCU hash algorithm test module.");
MODULE_LICENSE("GPL");

static int readers = -1; /* Number of reader tasks; defaults to online CPUs */
static unsigned long buckets = 1024; /* Number of hash table buckets */
static unsigned long entries = 4096; /* Number of entries initially added */

module_param(readers, int, 0444);
MODULE_PARM_DESC(readers, "Number of reader threads");
module_param(buckets, ulong, 0444);
MODULE_PARM_DESC(buckets, "Number of hash buckets");
module_param(entries, ulong, 0444);
MODULE_PARM_DESC(entries, "Number of hash table entries");

static struct hlist_head *hash_table;

struct rcuhashbash_entry {
	struct hlist_node node;
	struct rcu_head rcu_head;
	u32 value;
};

static struct kmem_cache *entry_cache;

static struct task_struct **reader_tasks;
static struct task_struct *writer_task;

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
struct writer_stats writer_stats;

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

static int rcuhashbash_reader(void *arg)
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
		hlist_for_each_entry_rcu(entry, node, &hash_table[value % buckets], node)
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

static void rcuhashbash_entry_cb(struct rcu_head *rcu_head)
{
	struct rcuhashbash_entry *entry;
	entry = container_of(rcu_head, struct rcuhashbash_entry, rcu_head);
	kmem_cache_free(entry_cache, entry);
}

static int rcuhashbash_writer(void *arg)
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
		struct rcuhashbash_entry *old_entry = NULL;
		struct hlist_node **src_tail = NULL;
		struct hlist_node **dst_tail = NULL;

		cond_resched();

		src_value = rcu_random(&rand) % (entries * 2);
		src_bucket = src_value % buckets;
		dst_value = rcu_random(&rand) % (entries * 2);
		dst_bucket = dst_value % buckets;
		same_bucket = src_bucket == dst_bucket;

		/* Find src_tail and src_entry. */
		src_tail = &(hash_table[src_bucket].first);
		hlist_for_each_entry(entry, node, &hash_table[src_bucket], node) {
			if (entry->value == src_value)
				src_entry = entry;
			if (same_bucket && entry->value == dst_value)
				dest_in_use = true;
			if (!entry->node.next)
				src_tail = &(entry->node.next);
		}
		if (!src_entry) {
			stats->misses++;
			continue;
		}
		if (dest_in_use) {
			stats->dests_in_use++;
			continue;
		}

		if (same_bucket) {
			src_entry->value = dst_value;
			stats->moves++;
			continue;
		}

		/* Find dst_tail and check for existing destination. */
		dst_tail = &(hash_table[dst_bucket].first);
		hlist_for_each_entry(entry, node, &hash_table[dst_bucket], node) {
			if (entry->value == dst_value) {
				dest_in_use = true;
				break;
			}
			if (!entry->node.next)
				dst_tail = &(entry->node.next);
		}
		if (dest_in_use) {
			stats->dests_in_use++;
			continue;
		}

		/* Move the entry to the end of its bucket. */
		if (src_entry->node.next) {
			old_entry = src_entry;
			src_entry = kmem_cache_zalloc(entry_cache, GFP_KERNEL);
			if (!src_entry)
				goto enomem;
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
	} while (!kthread_should_stop());

	return 0;

enomem:
	while (!kthread_should_stop())
		schedule_timeout_interruptible(1);
	return -ENOMEM;
}

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

	ws = writer_stats;

	printk(KERN_ALERT "rcuhashbash summary: %lu buckets, %lu entries\n"
	       KERN_ALERT "rcuhashbash summary: writer %llu moves %llu dests in use %llu misses\n"
	       KERN_ALERT "rcuhashbash summary: %d readers %llu hits %llu misses\n",
	       buckets, entries,
	       ws.moves, ws.dests_in_use, ws.misses,
	       readers, rs.hits, rs.misses);
}

static void rcuhashbash_exit(void)
{
	unsigned long i;
	int ret;

	if (writer_task) {
		ret = kthread_stop(writer_task);
		if(ret)
			printk(KERN_ALERT "rcuhashbash writer returned error %d\n", ret);
		writer_task = NULL;
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
			struct hlist_head *head = &hash_table[i];
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

	kfree(reader_stats);

	printk(KERN_ALERT "rcuhashbash done\n");
}

static __init int rcuhashbash_init(void)
{
	int ret;
	u32 i;

	entry_cache = KMEM_CACHE(rcuhashbash_entry, 0);
	if (!entry_cache)
		goto enomem;

	hash_table = kcalloc(buckets, sizeof(hash_table[0]), GFP_KERNEL);
	if (!hash_table)
		goto enomem;

	for (i = 0; i < entries; i++) {
		struct rcuhashbash_entry *entry;
		entry = kmem_cache_zalloc(entry_cache, GFP_KERNEL);
		if(!entry)
			goto enomem;
		entry->value = i;
		hlist_add_head(&entry->node, &hash_table[entry->value % buckets]);
	}

	if (readers < 0)
		readers = num_online_cpus();

	reader_stats = kcalloc(readers, sizeof(reader_stats[0]), GFP_KERNEL);
	if (!reader_stats)
		goto enomem;

	reader_tasks = kcalloc(readers, sizeof(reader_tasks[0]), GFP_KERNEL);
	if (!reader_tasks)
		goto enomem;

	printk(KERN_ALERT "rcuhashbash starting threads\n");

	for (i = 0; i < readers; i++) {
		struct task_struct *task;
		task = kthread_run(rcuhashbash_reader, &reader_stats[i],
		                   "rcuhashbash_reader");
		if (IS_ERR(task)) {
			ret = PTR_ERR(task);
			goto error;
		}
		reader_tasks[i] = task;
	}

	writer_task = kthread_run(rcuhashbash_writer, &writer_stats,
	                          "rcuhashbash_writer");
	if (IS_ERR(writer_task)) {
		ret = PTR_ERR(writer_task);
		writer_task = NULL;
		goto error;
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
