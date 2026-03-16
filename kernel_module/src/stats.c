#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/string.h>

#include "../include/traffic_analyzer.h"

/* global structures */
LIST_HEAD(traffic_list);
DEFINE_SPINLOCK(stats_lock);

static unsigned int traffic_entries = 0;

/* update statistics */
void stats_update(pid_t pid,
                  const char *comm,
                  __be32 dest,
                  u16 port,
                  u64 bytes)
{
    struct traffic_node *node;

    spin_lock(&stats_lock);

    /* search existing entry */
    list_for_each_entry(node, &traffic_list, list)
    {
        if (node->entry.pid == pid &&
            node->entry.dest_ip == dest &&
            node->entry.port == port)
        {
            node->entry.bytes += bytes;
            spin_unlock(&stats_lock);
            return;
        }
    }

    /* enforce entry limit */
    if (traffic_entries >= MAX_TRAFFIC_ENTRIES)
    {
        struct traffic_node *oldest;

        oldest = list_first_entry(&traffic_list, struct traffic_node, list);
        list_del(&oldest->list);
        kfree(oldest);
        traffic_entries--;
    }

    /* allocate new entry */
    node = kmalloc(sizeof(*node), GFP_ATOMIC);
    if (!node)
    {
        spin_unlock(&stats_lock);
        return;
    }

    /* initialize entry */
    node->entry.pid = pid;
    strscpy(node->entry.comm, comm, TASK_COMM_LEN);

    node->entry.dest_ip = dest;
    node->entry.port = port;
    node->entry.bytes = bytes;

    list_add(&node->list, &traffic_list);

    traffic_entries++;

    spin_unlock(&stats_lock);
}

/* cleanup all entries */
void stats_cleanup(void)
{
    struct traffic_node *node, *tmp;

    spin_lock(&stats_lock);

    list_for_each_entry_safe(node, tmp, &traffic_list, list)
    {
        list_del(&node->list);
        kfree(node);
    }

    traffic_entries = 0;

    spin_unlock(&stats_lock);
}