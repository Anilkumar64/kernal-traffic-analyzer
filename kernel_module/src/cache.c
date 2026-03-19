#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/hashtable.h>
#include "../include/cache.h"

DEFINE_HASHTABLE(file_pid_cache, CACHE_BITS);

static DEFINE_SPINLOCK(cache_lock);

void cache_init(void)
{
    hash_init(file_pid_cache);
}

pid_t cache_lookup(struct file *file)
{
    struct file_pid_map *entry;
    pid_t pid = 0;

    spin_lock(&cache_lock);

    hash_for_each_possible(file_pid_cache, entry, node, (unsigned long)file)
    {
        if (entry->file == file)
        {
            pid = entry->pid;
            break;
        }
    }

    spin_unlock(&cache_lock);
    return pid;
}

void cache_insert(struct file *file, pid_t pid)
{
    struct file_pid_map *entry;

    if (cache_lookup(file))
        return;

    entry = kmalloc(sizeof(*entry), GFP_ATOMIC);
    if (!entry)
        return;

    entry->file = file;
    entry->pid = pid;

    spin_lock(&cache_lock);
    hash_add(file_pid_cache, &entry->node, (unsigned long)file);
    spin_unlock(&cache_lock);
}

void cache_cleanup(void)
{
    struct file_pid_map *entry;
    struct hlist_node *tmp;
    int bkt;

    spin_lock(&cache_lock);

    hash_for_each_safe(file_pid_cache, bkt, tmp, entry, node)
    {
        hash_del(&entry->node);
        kfree(entry);
    }

    spin_unlock(&cache_lock);
}