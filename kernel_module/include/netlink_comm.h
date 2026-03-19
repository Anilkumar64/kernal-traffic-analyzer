#ifndef _NETLINK_COMM_H
#define _NETLINK_COMM_H

#include <linux/types.h>
#include <linux/netlink.h>

/* ================================================================
 * NETLINK FAMILY NUMBER
 *
 * We use NETLINK_USERSOCK (2) which is reserved for userspace use.
 * Userspace opens: socket(AF_NETLINK, SOCK_RAW, NETLINK_USERSOCK)
 *
 * For a production system you'd register a proper Generic Netlink
 * family.  For this module NETLINK_USERSOCK is simpler and avoids
 * needing genl_register_family() version differences across kernels.
 * ================================================================ */
#define TA_NETLINK_PROTO NETLINK_USERSOCK

/* ================================================================
 * MULTICAST GROUPS
 *
 * Userspace subscribes via setsockopt(NETLINK_ADD_MEMBERSHIP).
 * A listener can subscribe to one or more groups simultaneously.
 *
 * Group numbers must be 1-32 (kernel bitmask limitation).
 * ================================================================ */
#define TA_GROUP_CONNECTIONS 1 /* new / updated / closed connections */
#define TA_GROUP_ANOMALIES 2   /* anomaly alerts                     */
#define TA_GROUP_DNS 3         /* IP→domain resolution events        */
#define TA_GROUP_ROUTES 4      /* route hops populated               */

/* ================================================================
 * MESSAGE TYPES
 * ================================================================ */
enum ta_msg_type
{
    TA_MSG_CONN_NEW = 1,     /* new connection appeared             */
    TA_MSG_CONN_UPDATE = 2,  /* bytes / rate changed (throttled)    */
    TA_MSG_CONN_CLOSED = 3,  /* connection closed (FIN/RST)         */
    TA_MSG_ANOMALY = 4,      /* anomaly detected for a process      */
    TA_MSG_DNS_RESOLVED = 5, /* IP→domain learned from DNS response */
    TA_MSG_ROUTE_READY = 6,  /* route hops written by daemon        */
};

/* ================================================================
 * MESSAGE HEADER
 *
 * Every netlink message payload starts with this header.
 * Followed immediately by the message-type-specific payload.
 * ================================================================ */
struct ta_msg_hdr
{
    __u32 type;      /* enum ta_msg_type                     */
    __u32 len;       /* total payload length (hdr + body)    */
    __u64 timestamp; /* ktime_get_real_seconds()             */
};

/* ================================================================
 * TA_MSG_CONN_NEW / TA_MSG_CONN_UPDATE / TA_MSG_CONN_CLOSED
 * ================================================================ */
struct ta_msg_conn
{
    struct ta_msg_hdr hdr;

    __s32 pid;
    __u32 uid;
    char comm[16]; /* TASK_COMM_LEN */
    char exe[256];
    char domain[256];

    __u8 protocol; /* IPPROTO_TCP / IPPROTO_UDP */
    __u8 state;    /* enum conn_state           */
    __u8 is_dns;
    __u8 is_resolved;

    __be32 src_ip;
    __be32 dest_ip;
    __u16 src_port;
    __u16 dest_port;

    __u64 bytes_out;
    __u64 bytes_in;
    __u64 packets_out;
    __u64 packets_in;

    __u32 rate_out_bps;
    __u32 rate_in_bps;

    __u64 first_seen;
    __u64 last_seen;
    __u64 closed_at;
};

/* ================================================================
 * TA_MSG_ANOMALY
 * ================================================================ */
struct ta_msg_anomaly
{
    struct ta_msg_hdr hdr;

    __s32 pid;
    __u32 uid;
    char comm[16];
    char exe[256];

    __u8 anomaly_flags; /* bitmask ANOMALY_* */
    __u32 total_conns;
    __u32 syn_pending;
    __u32 new_conns_last_sec;
    __u8 unique_ports_last_sec;
    __u32 rate_out_bps;
    __u32 rate_in_bps;
};

/* ================================================================
 * TA_MSG_DNS_RESOLVED
 * ================================================================ */
struct ta_msg_dns
{
    struct ta_msg_hdr hdr;

    __be32 ip;
    char domain[256];
    __u32 ttl;
    __s32 queried_by_pid;
    char queried_by_comm[16];
};

/* ================================================================
 * TA_MSG_ROUTE_READY
 * ================================================================ */
#define TA_MAX_HOPS 32

struct ta_route_hop_msg
{
    __u8 hop_num;
    __be32 ip;
    char host[64];
    __u32 rtt_us;
    char city[64];
    char country[64];
    char country_code[4];
    __s32 lat_e6;
    __s32 lon_e6;
    char asn[16];
    char org[64];
};

struct ta_msg_route
{
    struct ta_msg_hdr hdr;
    __be32 dest_ip;
    char domain[256];
    __u8 hop_count;
    struct ta_route_hop_msg hops[TA_MAX_HOPS];
};

/* ================================================================
 * KERNEL-SIDE API (defined in netlink_comm.c)
 * ================================================================ */
#ifdef __KERNEL__

/*
 * The send functions reference struct traffic_entry, struct proc_entry,
 * and struct route_entry — which are defined in traffic_analyzer.h and
 * route_store.h.  Include them here so every .c that includes
 * netlink_comm.h sees complete struct definitions, not forward-declared
 * incomplete types.  Without this the compiler sees the parameter types
 * as unknown → "declared inside parameter list" → conflicting types error.
 */
#include "../include/traffic_analyzer.h"
#include "../include/route_store.h"

int ta_netlink_init(void);
void ta_netlink_cleanup(void);

/* Send functions — called from stats.c, dns_map.c, route_store.c */
void ta_nl_send_conn_new(const struct traffic_entry *e);
void ta_nl_send_conn_update(const struct traffic_entry *e);
void ta_nl_send_conn_closed(const struct traffic_entry *e);
void ta_nl_send_anomaly(const struct proc_entry *e);
void ta_nl_send_dns(__be32 ip, const char *domain,
                    u32 ttl, pid_t pid, const char *comm);
void ta_nl_send_route(const struct route_entry *e);

#endif /* __KERNEL__ */

#endif /* _NETLINK_COMM_H */