#ifndef _DNS_MAP_H
#define _DNS_MAP_H

#include <linux/types.h>
#include <linux/list.h>      /* struct hlist_node  */
#include <linux/hashtable.h> /* hash_for_each etc  */
#include <linux/seq_file.h>  /* struct seq_file    */
#include <linux/sched.h>     /* TASK_COMM_LEN      */

#define DNS_NAME_MAX 256
#define DNS_MAP_BITS 10
#define DNS_MAP_TTL 300 /* seconds — honour DNS TTL roughly */

/*
 * One A-record mapping: IPv4 address → domain name.
 * Populated by dns_parser when it sees DNS response packets.
 * Consumed by stats.c to annotate traffic_entry.domain.
 */
struct dns_entry
{
    __be32 ip;
    char name[DNS_NAME_MAX];
    u64 expires;          /* ktime_get_real_seconds() + ttl */
    pid_t queried_by_pid; /* PID that sent the DNS query    */
    char queried_by_comm[TASK_COMM_LEN];
    u64 first_seen;
    u64 last_seen;
    struct hlist_node node;
};

void dns_map_init(void);
void dns_map_cleanup(void);

void dns_map_insert(__be32 ip, const char *name, u32 ttl,
                    pid_t pid, const char *comm);
bool dns_map_lookup(__be32 ip, char *buf, size_t bufsz);
void dns_map_invalidate(__be32 ip);

/*
 * Iteration helpers for proc_interface seq_file output.
 * Call begin(), then seq_show(), then end() — always paired.
 */
void dns_map_for_each_begin(void);
void dns_map_for_each_end(void);
void dns_map_seq_show(struct seq_file *m);

#endif /* _DNS_MAP_H */