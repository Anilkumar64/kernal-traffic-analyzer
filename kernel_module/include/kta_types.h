/**
 * @file kta_types.h
 * @brief Shared data structures for the Kernel Traffic Analyzer module.
 * @details The module tracks bidirectional flows, per-process aggregates, DNS
 * mappings, route requests, and PID-resolution caches. These structs are kept
 * in one header so every subsystem agrees on layout and /proc serialization.
 * @author Kernel Traffic Analyzer Project
 * @license GPL-2.0
 */

#pragma once

#include <linux/hashtable.h>
#include <linux/ktime.h>
#include <linux/list.h>
#include <linux/types.h>
#include "kta_constants.h"

enum kta_conn_state {
	KTA_STATE_UNKNOWN,
	KTA_STATE_SYN_SENT,
	KTA_STATE_SYN_RECEIVED,
	KTA_STATE_ESTABLISHED,
	KTA_STATE_FIN_WAIT,
	KTA_STATE_CLOSED,
	KTA_STATE_TIME_WAIT,
	KTA_STATE_UDP
};

struct flow_key {
	__be32 src_ip, dst_ip;
	__be16 src_port, dst_port;
	u8 protocol;
	u8 pad[3];
};

struct traffic_entry {
	struct list_head list;
	struct flow_key key; /* canonical (lower IP = src) */
	pid_t pid;
	uid_t uid;
	char proc_name[MAX_PROC_NAME_LEN];
	char exe_path[MAX_EXE_PATH_LEN];
	char domain[MAX_DOMAIN_LEN];
	enum kta_conn_state state;
	u8 anomaly_flags;
	bool dns_resolved;
	bool pid_resolved;
	u64 bytes_in, bytes_out;
	u64 packets_in, packets_out;
	u64 bytes_in_prev, bytes_out_prev; /* for rate calculation */
	u64 rate_in, rate_out; /* bytes/sec */
	ktime_t first_seen, last_seen;
	unsigned long ttl_jiffies;
};

struct proc_entry {
	struct list_head list;
	pid_t pid;
	uid_t uid;
	char proc_name[MAX_PROC_NAME_LEN];
	u32 conn_count;
	u32 tcp_count, udp_count;
	u64 total_bytes_in, total_bytes_out;
	u64 rate_in, rate_out;
	u8 anomaly_flags;
	u32 new_conns_per_sec;
	u32 unique_dst_ports;
	u32 pending_syn_count;
	ktime_t first_seen;
};

struct dns_entry {
	struct hlist_node hnode;
	__be32 ip;
	char domain[MAX_DOMAIN_LEN];
	ktime_t first_seen, last_seen;
	u32 query_count;
};

struct route_entry {
	struct list_head list;
	__be32 target_ip;
	bool pending; /* true = awaiting daemon, false = completed */
	/* hop data - only valid when !pending */
	u8 hop_num;
	__be32 hop_ip;
	u32 rtt_ms;
	char country[8];
	char lat[16], lon[16];
	char asn[32];
	char org[64];
};

struct sock_cache_entry {
	struct hlist_node hnode;
	const struct sock *sk;
	pid_t pid;
	unsigned long accessed;
};

struct inode_cache_entry {
	struct hlist_node hnode;
	unsigned long inode;
	pid_t pid;
	unsigned long accessed;
};

struct flow_cache_entry {
	struct hlist_node hnode;
	struct flow_key key;
	pid_t pid;
	bool should_scan;
	unsigned long accessed;
};

struct exe_cache_entry {
	struct hlist_node hnode;
	pid_t pid;
	char path[MAX_EXE_PATH_LEN];
	unsigned long cached_jiffies;
};

