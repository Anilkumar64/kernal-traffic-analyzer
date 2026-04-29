#include <linux/slab.h>
#include <linux/jhash.h>
#include <linux/spinlock.h>
#include <linux/jiffies.h>
#include <linux/atomic.h>
#include "../include/flow_cache.h"

#define FLOW_HASH_BITS 10
#define FLOW_SCAN_COOLDOWN (HZ / 2) /* 500 ms */
#define FLOW_NEGATIVE_TTL (HZ * 2)  /* 2 sec  */
#define FLOW_CACHE_MAX_ENTRIES 4096
#define FLOW_CACHE_TTL_SEC 120
#define FLOW_CACHE_TTL_JIFFIES (FLOW_CACHE_TTL_SEC * HZ)

/*
 * DEFINE_HASHTABLE cannot be combined with static when the bit-width
 * comes from a #define — the macro stringifies the name and the
 * preprocessor misparses it.  Declare without static; the symbol is
 * local to this translation unit because it is not extern'd anywhere.
 */
static DEFINE_SPINLOCK(flow_lock);
DEFINE_HASHTABLE(flow_table, FLOW_HASH_BITS);
static atomic_t flow_cache_count = ATOMIC_INIT(0);

static u32 flow_hash(struct flow_key *key)
{
    return jhash(key, sizeof(*key), 0);
}

static inline bool flow_key_equal(struct flow_key *a, struct flow_key *b)
{
    return a->src_ip == b->src_ip &&
           a->dest_ip == b->dest_ip &&
           a->src_port == b->src_port &&
           a->dest_port == b->dest_port &&
           a->protocol == b->protocol;
}

void flow_cache_init(void)
{
    hash_init(flow_table);
    atomic_set(&flow_cache_count, 0);
}

static void flow_free_entry(struct flow_entry *entry)
{
    hash_del(&entry->node);
    kfree(entry);
    atomic_dec_if_positive(&flow_cache_count);
}

static void flow_evict_stale_locked(unsigned long now)
{
    struct flow_entry *entry;
    struct hlist_node *tmp;
    int bkt;

    hash_for_each_safe(flow_table, bkt, tmp, entry, node)
    {
        if (time_after(now, entry->last_seen + FLOW_CACHE_TTL_JIFFIES))
            flow_free_entry(entry);
    }
}

static void flow_evict_lru_locked(void)
{
    struct flow_entry *entry;
    struct flow_entry *oldest = NULL;
    int bkt;

    hash_for_each(flow_table, bkt, entry, node)
    {
        if (!oldest || time_before(entry->last_seen, oldest->last_seen))
            oldest = entry;
    }

    if (oldest)
        flow_free_entry(oldest);
}

bool flow_cache_exists(struct flow_key *key)
{
    struct flow_entry *entry;
    bool found = false;

    spin_lock(&flow_lock);
    flow_evict_stale_locked(jiffies);

    hash_for_each_possible(flow_table, entry, node, flow_hash(key))
    {
        if (flow_key_equal(&entry->key, key))
        {
            found = true;
            break;
        }
    }

    spin_unlock(&flow_lock);
    return found;
}

pid_t flow_cache_lookup(struct flow_key *key, bool *should_scan)
{
    struct flow_entry *entry;
    pid_t pid = 0;
    unsigned long now = jiffies;

    *should_scan = false;

    spin_lock(&flow_lock);
    flow_evict_stale_locked(now);

    hash_for_each_possible(flow_table, entry, node, flow_hash(key))
    {
        if (!flow_key_equal(&entry->key, key))
            continue;

        entry->last_seen = now;

        if (entry->pid > 0)
        {
            pid = entry->pid;
            goto out;
        }

        if (entry->negative)
        {
            if (time_before(now, entry->last_scan_time + FLOW_NEGATIVE_TTL))
                goto out;
        }

        if (entry->resolving)
            goto out;

        if (time_before(now, entry->last_scan_time + FLOW_SCAN_COOLDOWN))
            goto out;

        entry->resolving = true;
        entry->last_scan_time = now;
        *should_scan = true;
        goto out;
    }

    /* New entry */
    if (atomic_read(&flow_cache_count) >= FLOW_CACHE_MAX_ENTRIES)
        flow_evict_lru_locked();

    entry = kmalloc(sizeof(*entry), GFP_ATOMIC);
    if (entry)
    {
        entry->key = *key;
        entry->pid = 0;
        entry->last_seen = now;
        entry->last_scan_time = now;
        entry->resolving = true;
        entry->negative = false;
        hash_add(flow_table, &entry->node, flow_hash(key));
        atomic_inc(&flow_cache_count);
        *should_scan = true;
    }

out:
    spin_unlock(&flow_lock);
    return pid;
}

void flow_cache_mark_resolved(struct flow_key *key, pid_t pid)
{
    struct flow_entry *entry;
    unsigned long now = jiffies;

    spin_lock(&flow_lock);
    flow_evict_stale_locked(now);

    hash_for_each_possible(flow_table, entry, node, flow_hash(key))
    {
        if (!flow_key_equal(&entry->key, key))
            continue;
        entry->pid = pid;
        entry->last_seen = now;
        entry->resolving = false;
        entry->negative = false;
        goto out;
    }

    entry = kmalloc(sizeof(*entry), GFP_ATOMIC);
    if (entry)
    {
        if (atomic_read(&flow_cache_count) >= FLOW_CACHE_MAX_ENTRIES)
            flow_evict_lru_locked();
        entry->key = *key;
        entry->pid = pid;
        entry->last_seen = now;
        entry->last_scan_time = now;
        entry->resolving = false;
        entry->negative = false;
        hash_add(flow_table, &entry->node, flow_hash(key));
        atomic_inc(&flow_cache_count);
    }

out:
    spin_unlock(&flow_lock);
}

void flow_cache_mark_negative(struct flow_key *key)
{
    struct flow_entry *entry;

    spin_lock(&flow_lock);
    flow_evict_stale_locked(jiffies);

    hash_for_each_possible(flow_table, entry, node, flow_hash(key))
    {
        if (!flow_key_equal(&entry->key, key))
            continue;
        entry->pid = 0;
        entry->resolving = false;
        entry->negative = true;
        entry->last_scan_time = jiffies;
        break;
    }

    spin_unlock(&flow_lock);
}

void flow_cache_cleanup(void)
{
    struct flow_entry *entry;
    struct hlist_node *tmp;
    int bkt;

    spin_lock(&flow_lock);

    hash_for_each_safe(flow_table, bkt, tmp, entry, node)
    {
        hash_del(&entry->node);
        kfree(entry);
    }
    atomic_set(&flow_cache_count, 0);

    spin_unlock(&flow_lock);
}
