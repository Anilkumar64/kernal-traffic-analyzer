#include <linux/hashtable.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/jiffies.h>
#include <linux/kernel.h>
#include "../include/inode_cache.h"

#define INODE_CACHE_BITS 10
#define INODE_CACHE_TTL (HZ * 60) /* 60 seconds, same as sock_cache */

struct inode_pid_map
{
    unsigned long ino;
    pid_t pid;
    unsigned long inserted;
    struct hlist_node node;
};

static DEFINE_HASHTABLE(inode_cache, INODE_CACHE_BITS);
static DEFINE_SPINLOCK(inode_cache_lock);

void inode_cache_init(void)
{
    hash_init(inode_cache);
}

/*
 * __evict_stale_locked — remove entries past TTL.
 * Must be called with inode_cache_lock held.
 */
static void __evict_stale_locked(void)
{
    struct inode_pid_map *entry;
    struct hlist_node *tmp;
    int bkt;
    unsigned long now = jiffies;

    hash_for_each_safe(inode_cache, bkt, tmp, entry, node)
    {
        if (time_after(now, entry->inserted + INODE_CACHE_TTL))
        {
            hash_del(&entry->node);
            kfree(entry);
        }
    }
}

pid_t inode_cache_lookup(unsigned long ino)
{
    struct inode_pid_map *entry;
    unsigned long now = jiffies;
    pid_t pid = 0;

    spin_lock(&inode_cache_lock);

    hash_for_each_possible(inode_cache, entry, node, ino)
    {
        if (entry->ino != ino)
            continue;

        /* Evict expired entry — treat as miss */
        if (time_after(now, entry->inserted + INODE_CACHE_TTL))
        {
            hash_del(&entry->node);
            kfree(entry);
            break;
        }

        pid = entry->pid;
        break;
    }

    spin_unlock(&inode_cache_lock);
    return pid;
}

void inode_cache_insert(unsigned long ino, pid_t pid)
{
    struct inode_pid_map *entry, *cur;

    if (!ino || !pid)
        return;

    entry = kmalloc(sizeof(*entry), GFP_ATOMIC);
    if (!entry)
        return;

    entry->ino = ino;
    entry->pid = pid;
    entry->inserted = jiffies;

    spin_lock(&inode_cache_lock);
    __evict_stale_locked();

    /* Check for duplicate inside lock to avoid TOCTOU race */
    hash_for_each_possible(inode_cache, cur, node, ino)
    {
        if (cur->ino == ino)
        {
            spin_unlock(&inode_cache_lock);
            kfree(entry);
            return;
        }
    }

    hash_add(inode_cache, &entry->node, ino);
    spin_unlock(&inode_cache_lock);
}

void inode_cache_invalidate(unsigned long ino)
{
    struct inode_pid_map *entry;
    struct hlist_node *tmp;

    spin_lock(&inode_cache_lock);

    hash_for_each_possible_safe(inode_cache, entry, tmp, node, ino)
    {
        if (entry->ino == ino)
        {
            hash_del(&entry->node);
            kfree(entry);
            break;
        }
    }

    spin_unlock(&inode_cache_lock);
}

void inode_cache_cleanup(void)
{
    struct inode_pid_map *entry;
    struct hlist_node *tmp;
    int bkt;

    spin_lock(&inode_cache_lock);

    hash_for_each_safe(inode_cache, bkt, tmp, entry, node)
    {
        hash_del(&entry->node);
        kfree(entry);
    }

    spin_unlock(&inode_cache_lock);
}