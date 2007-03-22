/* rcuhashbash: test module for RCU hash-table alorithms.
 * Written by Josh Triplett
 * Mostly lockless random number generator rcu_random by Paul McKenney and Josh
 * Triplett, from rcutorture.
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
MODULE_LICENSE("GPL v2");

/* static DEFINE_SPINLOCK(hash_lock); */
static HLIST_HEAD(head);

struct rcuhashbash_entry {
	struct hlist_node node;
	u32 value;
};

static struct kmem_cache *entry_cache;

static struct task_struct *reader_task;
static struct task_struct *writer_task;

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
 * generator, with occasional help from get_random_bytes().
 */
static unsigned long
rcu_random(struct rcu_random_state *rrsp)
{
        long refresh;

        if (--rrsp->rrs_count < 0) {
                get_random_bytes(&refresh, sizeof(refresh));
                rrsp->rrs_state += refresh;
                rrsp->rrs_count = RCU_RANDOM_REFRESH;
        }
        rrsp->rrs_state = rrsp->rrs_state * RCU_RANDOM_MULT + RCU_RANDOM_ADD;
        return swahw32(rrsp->rrs_state);
}

static int rcuhashbash_reader(void *arg)
{
	set_user_nice(current, 19);
	do {
		bool seen[16] = { [0 ... 15] = false };
		struct rcuhashbash_entry *entry;
		struct hlist_node *node;
		u32 i;

		rcu_read_lock();
		hlist_for_each_entry_rcu(entry, node, &head, node) {
			if (entry->value >= 16)
				printk(KERN_ALERT "rcuhashbash: reader found unexpected node with value %u\n", entry->value);
			else
				seen[entry->value] = true;
		}
		rcu_read_unlock();

		for (i = 0; i < 16; i++)
			if (!seen[i])
				printk(KERN_ALERT "rcuhashbash: reader missed element %u", i);
	} while (!kthread_should_stop());
	return 0;
}

static int rcuhashbash_writer(void *arg)
{
	DEFINE_RCU_RANDOM(rand);
	set_user_nice(current, 19);
	do {
		struct rcuhashbash_entry *entry = NULL;
		struct rcuhashbash_entry *newentry = NULL;
		struct rcuhashbash_entry *tail = NULL;
		struct hlist_node *node;
		u32 n = rcu_random(&rand) % 16;
		hlist_for_each_entry(tail, node, &head, node) {
			if (tail->value == n)
				entry = tail;
			if (!tail->node.next)
				break;
		}
		if (entry != tail) {
			newentry = kmem_cache_alloc(entry_cache, GFP_KERNEL);
			if (!newentry)
				return -ENOMEM;
			newentry->value = entry->value;
			INIT_HLIST_NODE(&newentry->node);
			hlist_add_after_rcu(&tail->node, &newentry->node);
			smp_wmb(); /* New entry must appear before old disappears. */
			hlist_del_rcu(&entry->node);
			synchronize_rcu();
			kmem_cache_free(entry_cache, entry);
		}
	} while (!kthread_should_stop());
	return 0;
}

static void rcuhashbash_exit(void)
{
	if (writer_task) {
		kthread_stop(writer_task);
		writer_task = NULL;
	}

	if (reader_task) {
		kthread_stop(reader_task);
		reader_task = NULL;
	}

	while (!hlist_empty(&head)) {
		struct rcuhashbash_entry *entry = hlist_entry(head.first, struct rcuhashbash_entry, node);
		hlist_del(&entry->node);
		kmem_cache_free(entry_cache, entry);
	}

	if (entry_cache)
		kmem_cache_destroy(entry_cache);
}

static __init int rcuhashbash_init(void)
{
	int ret;
	u32 i;
	entry_cache = kmem_cache_create("rcuhashbash_entry",
	                                sizeof(struct rcuhashbash_entry),
					0, 0, NULL, NULL);
	if (!entry_cache)
		return -ENOMEM;
	
	for (i = 0; i < 16; i++) {
		struct rcuhashbash_entry *entry;
		entry = kmem_cache_alloc(entry_cache, GFP_KERNEL);
		if(!entry) {
			ret = -ENOMEM;
			goto unwind;
		}
		entry->value = i;
		hlist_add_head(&entry->node, &head);
	}

        reader_task = kthread_run(rcuhashbash_reader, NULL,
                                  "rcuhashbash_reader");
        if (IS_ERR(reader_task)) {
                ret = PTR_ERR(reader_task);
                reader_task = NULL;
                goto unwind;
        }	
	
        writer_task = kthread_run(rcuhashbash_writer, NULL,
                                  "rcuhashbash_writer");
        if (IS_ERR(writer_task)) {
                ret = PTR_ERR(writer_task);
                writer_task = NULL;
                goto unwind;
        }	
	
	return 0;

unwind:
	rcuhashbash_exit();
	return ret;
}

module_init(rcuhashbash_init);
module_exit(rcuhashbash_exit);
