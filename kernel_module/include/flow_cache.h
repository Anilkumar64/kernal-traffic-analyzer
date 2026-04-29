#ifndef _FLOW_CACHE_H
#define _FLOW_CACHE_H

#include <linux/types.h>
#include <linux/list.h>      /* struct hlist_node                  */
#include <linux/hashtable.h> /* hash_for_each_possible, hash_add … */

struct flow_key
{
    __be32 src_ip;
    __be32 dest_ip;
    __be16 src_port;
    __be16 dest_port;
    __u8 protocol;
};

struct flow_entry
{
    struct flow_key key;
    pid_t pid;
    unsigned long last_seen;
    unsigned long last_scan_time;
    bool resolving;
    bool negative;
    struct hlist_node node;
};

void flow_cache_init(void);
void flow_cache_cleanup(void);
bool flow_cache_exists(struct flow_key *key);
pid_t flow_cache_lookup(struct flow_key *key, bool *should_scan);
void flow_cache_mark_resolved(struct flow_key *key, pid_t pid);
void flow_cache_mark_negative(struct flow_key *key);

#endif /* _FLOW_CACHE_H */
