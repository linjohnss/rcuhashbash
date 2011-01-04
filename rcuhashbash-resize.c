/* rcuhashbash-resize: test module for RCU hash-table resize alorithms.
 * Written by Josh Triplett
 * Mostly lockless random number generator rcu_random from rcutorture, by Paul
 * McKenney and Josh Triplett.
 */
#include <linux/init.h>
#include <linux/kthread.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/random.h>
#include <linux/rcupdate.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <asm/byteorder.h>

MODULE_AUTHOR("Josh Triplett <josh@kernel.org>");
MODULE_DESCRIPTION("RCU hash table resizing algorithm test module.");
MODULE_LICENSE("GPL");

static char *test = "rcu"; /* Hash table implementation to benchmark */
static int readers = -1;
static bool resize = true;
static u8 shift1 = 13;
static u8 shift2 = 14;
static unsigned long entries = 65536;

module_param(test, charp, 0444);
MODULE_PARM_DESC(test, "Hash table implementation");
module_param(readers, int, 0444);
MODULE_PARM_DESC(readers, "Number of reader threads (default: number of online CPUs)");
module_param(resize, bool, 0444);
MODULE_PARM_DESC(resize, "Whether to run a resize thread (default: true)");
module_param(shift1, byte, 0444);
MODULE_PARM_DESC(shift1, "Initial number of hash buckets, log 2");
module_param(shift2, byte, 0444);
MODULE_PARM_DESC(shift2, "Number of hash buckets after resize, log 2");
module_param(entries, ulong, 0444);
MODULE_PARM_DESC(entries, "Number of hash table entries");

struct rcuhashbash_table {
	unsigned long mask;
	struct hlist_head buckets[];
};

struct stats {
	u64 read_hits;
	u64 read_hits_fallback;
	u64 read_misses;
	u64 resizes;
};

struct rcuhashbash_ops {
	const char *test;
	int (*read)(u32 value, struct stats *stats);
	int (*resize)(u8 new_buckets_shift, struct stats *stats);
};

static struct rcuhashbash_ops *ops;

static struct rcuhashbash_table *table;
static struct rcuhashbash_table *table2;

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

static bool rcuhashbash_try_lookup(struct rcuhashbash_table *t, u32 value)
{
	struct rcuhashbash_entry *entry;
	struct hlist_node *node;

	hlist_for_each_entry_rcu(entry, node, &t->buckets[value & t->mask], node)
		if (entry->value == value)
			return true;
	return false;
}

static int rcuhashbash_read_rcu(u32 value, struct stats *stats)
{
	rcu_read_lock();
	if (rcuhashbash_try_lookup(rcu_dereference(table), value))
		stats->read_hits++;
	else {
		struct rcuhashbash_table *table2_local = rcu_dereference(table2);
		if (unlikely(table2_local) && rcuhashbash_try_lookup(table2_local, value))
			stats->read_hits_fallback++;
		else
			stats->read_misses++;
	}
	rcu_read_unlock();

	return 0;
}

static struct hlist_node **hlist_advance_last_next(struct hlist_node **old_last_next)
{
	struct hlist_head h = { .first = *old_last_next };
	struct hlist_node *node;

	hlist_for_each(node, &h)
		if (!node->next)
			return &node->next;
	/* If we get here, we had an empty list. */
	return old_last_next;
}

static int rcuhashbash_resize(u8 new_buckets_shift, struct stats *stats)
{
	unsigned long len2 = 1UL << new_buckets_shift;
	unsigned long mask2 = len2 - 1;
	unsigned long i, j;

	if (mask2 < table->mask) {
		/* Shrink. */
		struct rcuhashbash_table *new_table;
		for (i = 0; i <= mask2; i++) {
			struct hlist_node **last_next = &table->buckets[i].first;
			for (j = i + len2; j <= table->mask; j += len2) {
				if (hlist_empty(&table->buckets[j]))
					continue;
				last_next = hlist_advance_last_next(last_next);
				*last_next = table->buckets[j].first;
				(*last_next)->pprev = last_next;
			}
		}
		/* Force the readers to see the new links before the
		 * new mask. smp_wmb() does not suffice since the
		 * readers do not smp_rmb(). */
		synchronize_rcu();
		table->mask = mask2;
		synchronize_rcu();
		/* Assume (and assert) that __krealloc shrinks in place. */
		new_table = __krealloc(table, sizeof(*table) + len2 * sizeof(table->buckets[0]), GFP_KERNEL);
		BUG_ON(new_table != table);
	} else if (mask2 > table->mask) {
		/* Grow. */
		struct rcuhashbash_table *temp_table;
		bool moved_one;
		/* Explicitly avoid in-place growth, to simplify the algorithm. */
		temp_table = kzalloc(sizeof(*table) + len2 * sizeof(table->buckets[0]), GFP_KERNEL);
		temp_table->mask = mask2;
		rcu_assign_pointer(table2, temp_table);

		/* Move nodes. */
		while (true) {
			moved_one = false;
			/* Move a suffix of nodes from each bucket. */
			for (i = 0; i <= table->mask; i++) {
				struct rcuhashbash_entry *entry;
				struct hlist_node *node;
				struct hlist_node *suffix_start = NULL;
				struct hlist_node *last;
				unsigned long target_bucket = ~0UL;

				if (hlist_empty(&table->buckets[i]))
					continue;
				moved_one = true;

				suffix_start = NULL;
				hlist_for_each_entry(entry, node, &table->buckets[i], node) {
					if (!suffix_start || (entry->value & table2->mask) != target_bucket) {
						suffix_start = node;
						target_bucket = entry->value & table2->mask;
					}
					last = node;
				}

				last->next = table2->buckets[target_bucket].first;
				if (last->next)
					last->next->pprev = &last->next;
				rcu_assign_pointer(table2->buckets[target_bucket].first, suffix_start);
				/* Don't set table2->buckets[i].first->pprev
				 * yet; use it to find the suffix in the next
				 * pass to un-cross-link. */
			}
			if (!moved_one)
				break;

			/* Make sure current readers can successfully finish,
			 * finding nodes via the cross-links. */
			synchronize_rcu();
			/* Fix all the cross-linking. */
			for (i = 0; i <= table2->mask; i++)
				if (table2->buckets[i].first && table2->buckets[i].first->pprev != &table2->buckets[i].first) {
					*table2->buckets[i].first->pprev = NULL;
					table2->buckets[i].first->pprev = &table2->buckets[i].first;
				}
		}

		/* Make the larger table the new primary table. */
		temp_table = table;
		rcu_assign_pointer(table, table2);
		synchronize_rcu();
		kfree(temp_table);
		table2 = NULL;
	}

	stats->resizes++;
	return 0;
}

static int rcuhashbash_read_thread(void *arg)
{
	int err;
	struct stats *stats_ret = arg;
	struct stats stats = {};
	DEFINE_RCU_RANDOM(rand);

	set_user_nice(current, 19);

	do {
		cond_resched();
		err = ops->read(rcu_random(&rand) % entries, &stats);
	} while (!kthread_should_stop() && !err);

	*stats_ret = stats;

	while (!kthread_should_stop())
		schedule_timeout_interruptible(1);
	return err;
}

static int rcuhashbash_resize_thread(void *arg)
{
	int err;
	struct stats *stats_ret = arg;
	struct stats stats = {};

	set_user_nice(current, 19);

	do {
		cond_resched();
		err = ops->resize(table->mask == (1UL << shift1) - 1 ? shift2 : shift1, &stats);
	} while (!kthread_should_stop() && !err);

	*stats_ret = stats;

	while (!kthread_should_stop())
		schedule_timeout_interruptible(1);
	return err;
}

static struct rcuhashbash_ops all_ops[] = {
	{
		.test = "rcu",
		.read = rcuhashbash_read_rcu,
		.resize = rcuhashbash_resize,
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

	for (i = 0; i < readers + resize; i++) {
		s.read_hits += thread_stats[i].read_hits;
		s.read_hits_fallback += thread_stats[i].read_hits_fallback;
		s.read_misses += thread_stats[i].read_misses;
		s.resizes += thread_stats[i].resizes;
	}

	printk(KERN_ALERT
	       "rcuhashbash summary: test=%s readers=%d resize=%s\n"
	       "rcuhashbash summary: entries=%lu shift1=%u (%lu buckets) shift2=%u (%lu buckets)\n"
	       "rcuhashbash summary: reads: %llu primary hits, %llu fallback hits, %llu misses\n"
	       "rcuhashbash summary: resizes: %llu\n"
	       "rcuhashbash summary: %s\n",
	       test, readers, resize ? "true" : "false",
	       entries, shift1, 1UL << shift1, shift2, 1UL << shift2,
	       s.read_hits, s.read_hits_fallback, s.read_misses,
	       s.resizes,
	       s.read_misses == 0 ? "PASS" : "FAIL");
}

static void rcuhashbash_exit(void)
{
	unsigned long i;
	int ret;

	if (tasks) {
		for (i = 0; i < readers + resize; i++)
			if (tasks[i]) {
				ret = kthread_stop(tasks[i]);
				if(ret)
					printk(KERN_ALERT "rcuhashbash task returned error %d\n", ret);
			}
		kfree(tasks);
	}

	/* Wait for all RCU callbacks to complete. */
	rcu_barrier();

	if (table2) {
		printk(KERN_ALERT "rcuhashbash FAIL: secondary table still exists during cleanup.\n");
		kfree(table2);
	}

	if (table) {
		for (i = 0; i <= table->mask; i++) {
			struct hlist_head *head = &table->buckets[i];
			while (!hlist_empty(head)) {
				struct rcuhashbash_entry *entry;
				entry = hlist_entry(head->first, struct rcuhashbash_entry, node);
				hlist_del(head->first);
				kmem_cache_free(entry_cache, entry);
			}
		}
		kfree(table);
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
	unsigned long i;

	for (i = 0; i < ARRAY_SIZE(all_ops); i++)
		if (strcmp(test, all_ops[i].test) == 0) {
			ops = &all_ops[i];
		}
	if (!ops) {
		printk(KERN_ALERT "rcuhashbash: No implementation with test=%s\n",
		       test);
		return -EINVAL;
	}

	if (readers < 0)
		readers = num_online_cpus();

	if (!ops->read) {
		printk(KERN_ALERT "rcuhashbash: Internal error: read function NULL\n");
		return -EINVAL;
	}
	if (!ops->resize) {
		printk(KERN_ALERT "rcuhashbash: Internal error: resize function NULL\n");
		return -EINVAL;
	}

	entry_cache = KMEM_CACHE(rcuhashbash_entry, 0);
	if (!entry_cache)
		goto enomem;

	table = kzalloc(sizeof(*table) + (1UL << shift1) * sizeof(table->buckets[0]), GFP_KERNEL);
	if (!table)
		goto enomem;

	table->mask = (1UL << shift1) - 1;

	for (i = 0; i < entries; i++) {
		struct rcuhashbash_entry *entry;
		entry = kmem_cache_zalloc(entry_cache, GFP_KERNEL);
		if(!entry)
			goto enomem;
		entry->value = i;
		hlist_add_head(&entry->node, &table->buckets[i & table->mask]);
	}

	thread_stats = kcalloc(readers + resize, sizeof(thread_stats[0]), GFP_KERNEL);
	if (!thread_stats)
		goto enomem;

	tasks = kcalloc(readers + resize, sizeof(tasks[0]), GFP_KERNEL);
	if (!tasks)
		goto enomem;

	printk(KERN_ALERT "rcuhashbash starting threads\n");

	for (i = 0; i < readers + resize; i++) {
		struct task_struct *task;
		if (i < readers)
			task = kthread_run(rcuhashbash_read_thread,
			                   &thread_stats[i],
			                   "rcuhashbash_read");
		else
			task = kthread_run(rcuhashbash_resize_thread,
			                   &thread_stats[i],
			                   "rcuhashbash_resize");
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
