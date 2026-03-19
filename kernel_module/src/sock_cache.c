#include <linux/hashtable.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/jiffies.h>
#include "../include/sock_cache.h"

#define SOCK_CACHE_BITS 10
#define SOCK_CACHE_TTL (HZ * 60)

struct sock_pid_map
{
    struct sock *sk;
    pid_t pid;
    unsigned long inserted;
    struct hlist_node node;
};

static DEFINE_HASHTABLE(sock_cache, SOCK_CACHE_BITS);
static DEFINE_SPINLOCK(sock_cache_lock);

void sock_cache_init(void)
{
    hash_init(sock_cache);
}

static void __evict_stale_locked(void)
{
    struct sock_pid_map *entry;
    struct hlist_node *tmp;
    int bkt;
    unsigned long now = jiffies;

    hash_for_each_safe(sock_cache, bkt, tmp, entry, node)
    {
        if (time_after(now, entry->inserted + SOCK_CACHE_TTL))
        {
            hash_del(&entry->node);
            kfree(entry);
        }
    }
}

void sock_cache_insert(struct sock *sk, pid_t pid)
{
    struct sock_pid_map *entry;

    entry = kmalloc(sizeof(*entry), GFP_ATOMIC);
    if (!entry)
        return;

    entry->sk = sk;
    entry->pid = pid;
    entry->inserted = jiffies;

    spin_lock(&sock_cache_lock);
    __evict_stale_locked();
    hash_add(sock_cache, &entry->node, (unsigned long)sk);
    spin_unlock(&sock_cache_lock);
}

pid_t sock_cache_lookup(struct sock *sk)
{
    struct sock_pid_map *entry;
    unsigned long now = jiffies;

    spin_lock(&sock_cache_lock);

    hash_for_each_possible(sock_cache, entry, node, (unsigned long)sk)
    {
        if (entry->sk != sk)
            continue;

        if (time_after(now, entry->inserted + SOCK_CACHE_TTL))
        {
            hash_del(&entry->node);
            kfree(entry);
            break;
        }

        spin_unlock(&sock_cache_lock);
        return entry->pid;
    }

    spin_unlock(&sock_cache_lock);
    return 0;
}

void sock_cache_cleanup(void)
{
    struct sock_pid_map *entry;
    struct hlist_node *tmp;
    int bkt;

    spin_lock(&sock_cache_lock);

    hash_for_each_safe(sock_cache, bkt, tmp, entry, node)
    {
        hash_del(&entry->node);
        kfree(entry);
    }

    spin_unlock(&sock_cache_lock);
}