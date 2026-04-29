/**
 * @file kta_api.h
 * @brief Public subsystem interfaces for the Kernel Traffic Analyzer module.
 * @details This header exposes init/exit, lookup, update, parser, and /proc
 * helper APIs used across module boundaries. It intentionally keeps ownership
 * in the subsystem C files while allowing packet parsing, caches, and stats to
 * cooperate without private header coupling.
 * @author Kernel Traffic Analyzer Project
 * @license GPL-2.0
 */

#pragma once

#include <linux/seq_file.h>
#include <linux/skbuff.h>
#include <linux/socket.h>
#include <net/sock.h>
#include "kta_types.h"

/* dns_map.c */
int dns_map_init(void);
void dns_map_exit(void);
void dns_map_store(__be32 ip, const char *domain);
bool dns_map_lookup(__be32 ip, char *out, size_t outlen);
void dns_map_seq_show(struct seq_file *m);
u32 dns_map_count(void);

/* dns_parser.c */
void dns_parse_response(const struct sk_buff *skb, unsigned int data_offset);

/* sock_cache.c */
int sock_cache_init(void);
void sock_cache_exit(void);
pid_t sock_cache_lookup(const struct sock *sk);
void sock_cache_store(const struct sock *sk, pid_t pid);
void sock_cache_invalidate(const struct sock *sk);

/* inode_cache.c */
int inode_cache_init(void);
void inode_cache_exit(void);
pid_t inode_cache_lookup(unsigned long ino);
void inode_cache_store(unsigned long ino, pid_t pid);

/* flow_cache.c */
int flow_cache_init(void);
void flow_cache_exit(void);
pid_t flow_cache_lookup(const struct flow_key *key);
void flow_cache_store(const struct flow_key *key, pid_t pid);
bool flow_cache_should_scan(const struct flow_key *key);
void flow_cache_set_scanned(const struct flow_key *key);

/* exe_resolver.c */
int exe_cache_init(void);
void exe_cache_exit(void);
void exe_cache_get(pid_t pid, char *out, size_t outlen);

/* resolver.c */
int resolver_init(void);
void resolver_exit(void);
void resolver_schedule(const struct flow_key *key);

/* route_store.c */
int route_store_init(void);
void route_store_exit(void);
void route_store_request(__be32 ip);
bool route_store_is_pending(__be32 ip);
bool route_store_is_done(__be32 ip);
int route_store_write_result(const char *line, size_t len);
void route_store_seq_show_routes(struct seq_file *m);
void route_store_seq_show_pending(struct seq_file *m);
u32 route_store_done_count(void);

/* stats.c */
int stats_init(void);
void stats_exit(void);
void stats_update(const struct flow_key *key, pid_t pid, uid_t uid,
		  const char *proc_name, u32 pkt_len, bool is_inbound,
		  enum kta_conn_state state);
u64 stats_get_total_packets(void);
u64 stats_get_total_bytes(void);
void stats_seq_show_connections(struct seq_file *m);
void stats_seq_show_processes(struct seq_file *m);
void stats_seq_show_anomalies(struct seq_file *m);
u32 stats_get_active_connections(void);
u32 stats_get_active_processes(void);
u64 stats_get_uptime_sec(void);

/* proc_interface.c */
int proc_init(void);
void proc_exit(void);

/* netfilter_hook.c */
int nf_hook_init(void);
void nf_hook_exit(void);

/* packet_parser.c */
void parse_packet(struct sk_buff *skb, bool is_inbound);
pid_t resolve_pid_4tier(const struct flow_key *key, const struct sock *sk);
void make_canonical(struct flow_key *key);

