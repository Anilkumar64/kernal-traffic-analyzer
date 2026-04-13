#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/hashtable.h>
#include <linux/jhash.h>
#include <linux/timekeeping.h>
#include <linux/string.h>
#include "../include/dns_map.h"
#include "../include/netlink_comm.h" /* PHASE 6 */

static DEFINE_HASHTABLE(dns_table, DNS_MAP_BITS);
static DEFINE_SPINLOCK(dns_lock);

void dns_map_init(void)
{
    hash_init(dns_table);
}

void dns_map_insert(__be32 ip, const char *name, u32 ttl,
                    pid_t pid, const char *comm)
{
    struct dns_entry *entry;
    u64 now = ktime_get_real_seconds();
    u64 expiry = now + (ttl ? ttl : DNS_MAP_TTL);
    u32 hash = jhash(&ip, sizeof(ip), 0);

    if (!name || !name[0])
        return;

    spin_lock(&dns_lock);

    hash_for_each_possible(dns_table, entry, node, hash)
    {
        if (entry->ip != ip)
            continue;

        strscpy(entry->name, name, DNS_NAME_MAX);
        entry->expires = expiry;
        entry->last_seen = now;
        entry->queried_by_pid = pid;
        if (comm)
            strscpy(entry->queried_by_comm, comm, TASK_COMM_LEN);

        spin_unlock(&dns_lock);

        /* PHASE 6: notify on update */
        ta_nl_send_dns(ip, name, ttl, pid, comm);
        return;
    }

    spin_unlock(&dns_lock);

    entry = kmalloc(sizeof(*entry), GFP_ATOMIC);
    if (!entry)
        return;

    entry->ip = ip;
    entry->expires = expiry;
    entry->first_seen = now;
    entry->last_seen = now;
    entry->queried_by_pid = pid;
    strscpy(entry->name, name, DNS_NAME_MAX);
    if (comm)
        strscpy(entry->queried_by_comm, comm, TASK_COMM_LEN);
    else
        entry->queried_by_comm[0] = '\0';

    spin_lock(&dns_lock);
    /* Re-check: another CPU may have inserted the same IP while we allocated */
    {
        struct dns_entry *existing;
        hash_for_each_possible(dns_table, existing, node, hash)
        {
            if (existing->ip == ip)
            {
                spin_unlock(&dns_lock);
                kfree(entry);
                goto notify;
            }
        }
    }
    hash_add(dns_table, &entry->node, hash);
    spin_unlock(&dns_lock);

notify:
    /* PHASE 6: notify on new entry */
    ta_nl_send_dns(ip, name, ttl, pid, comm);
}

bool dns_map_lookup(__be32 ip, char *buf, size_t bufsz)
{
    struct dns_entry *entry;
    struct hlist_node *tmp;
    u64 now = ktime_get_real_seconds();
    u32 hash = jhash(&ip, sizeof(ip), 0);
    bool found = false;

    spin_lock(&dns_lock);

    hash_for_each_possible_safe(dns_table, entry, tmp, node, hash)
    {
        if (entry->ip != ip)
            continue;

        if (now >= entry->expires)
        {
            hash_del(&entry->node);
            kfree(entry);
            break;
        }

        if (buf && bufsz)
            strscpy(buf, entry->name, bufsz);

        found = true;
        break;
    }

    spin_unlock(&dns_lock);
    return found;
}

void dns_map_invalidate(__be32 ip)
{
    struct dns_entry *entry;
    struct hlist_node *tmp;
    u32 hash = jhash(&ip, sizeof(ip), 0);

    spin_lock(&dns_lock);

    hash_for_each_possible_safe(dns_table, entry, tmp, node, hash)
    {
        if (entry->ip == ip)
        {
            hash_del(&entry->node);
            kfree(entry);
            break;
        }
    }

    spin_unlock(&dns_lock);
}

void dns_map_cleanup(void)
{
    struct dns_entry *entry;
    struct hlist_node *tmp;
    int bkt;

    spin_lock(&dns_lock);

    hash_for_each_safe(dns_table, bkt, tmp, entry, node)
    {
        hash_del(&entry->node);
        kfree(entry);
    }

    spin_unlock(&dns_lock);
}

void dns_map_for_each_begin(void) { spin_lock_bh(&dns_lock); }
void dns_map_for_each_end(void) { spin_unlock_bh(&dns_lock); }

void dns_map_seq_show(struct seq_file *m)
{
    struct dns_entry *entry;
    u64 now = ktime_get_real_seconds();
    int bkt;

    hash_for_each(dns_table, bkt, entry, node)
    {
        if (now >= entry->expires)
            continue;

        seq_printf(m,
                   "%s|%pI4|%llu|%d|%s|%llu|%llu\n",
                   entry->name,
                   &entry->ip,
                   entry->expires - now,
                   entry->queried_by_pid,
                   entry->queried_by_comm,
                   entry->first_seen,
                   entry->last_seen);
    }
}