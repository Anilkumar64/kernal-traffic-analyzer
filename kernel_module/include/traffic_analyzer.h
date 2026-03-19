#ifndef _TRAFFIC_ANALYZER_H
#define _TRAFFIC_ANALYZER_H

#include <linux/types.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/sched.h>
#include <linux/skbuff.h>
#include <linux/in.h>

/* ================================================================
 * TUNABLES
 * ================================================================ */
#define MAX_TRAFFIC_ENTRIES 2048
#define MAX_PROC_ENTRIES 512

#define CONN_TTL_SYN 5
#define CONN_TTL_CLOSED 10
#define CONN_TTL_FIN_WAIT 15
#define CONN_TTL_ACTIVE 120
#define CONN_TTL_UDP 30
#define RATE_WINDOW_SECS 1

#define ANOMALY_CONN_BURST 20
#define ANOMALY_MAX_CONNS 200
#define ANOMALY_SYN_RATIO 80
#define ANOMALY_PORT_SCAN_PORTS 15
#define PROC_TOP_CONNS 5
#define EXE_PATH_MAX 256
#define DOMAIN_NAME_MAX 256

/* ================================================================
 * CONNECTION STATE
 * ================================================================ */
enum conn_state
{
    CONN_STATE_SYN_SENT = 0,
    CONN_STATE_SYN_RECV = 1,
    CONN_STATE_ESTABLISHED = 2,
    CONN_STATE_FIN_WAIT = 3,
    CONN_STATE_CLOSED = 4,
    CONN_STATE_UDP_ACTIVE = 5,
};

static inline const char *conn_state_str(enum conn_state s)
{
    switch (s)
    {
    case CONN_STATE_SYN_SENT:
        return "SYN_SENT";
    case CONN_STATE_SYN_RECV:
        return "SYN_RECV";
    case CONN_STATE_ESTABLISHED:
        return "ESTABLISHED";
    case CONN_STATE_FIN_WAIT:
        return "FIN_WAIT";
    case CONN_STATE_CLOSED:
        return "CLOSED";
    case CONN_STATE_UDP_ACTIVE:
        return "UDP_ACTIVE";
    default:
        return "UNKNOWN";
    }
}

/* ================================================================
 * ANOMALY FLAGS
 * ================================================================ */
#define ANOMALY_NONE 0x00
#define ANOMALY_CONN_BURST_FL 0x01
#define ANOMALY_PORT_SCAN_FL 0x02
#define ANOMALY_HIGH_CONNS_FL 0x04
#define ANOMALY_SYN_FLOOD_FL 0x08
#define ANOMALY_HIGH_BW_FL 0x10

static inline const char *anomaly_str(u8 flags)
{
    if (flags == ANOMALY_NONE)
        return "NONE";
    if (flags & ANOMALY_PORT_SCAN_FL)
        return "PORT_SCAN";
    if (flags & ANOMALY_SYN_FLOOD_FL)
        return "SYN_FLOOD";
    if (flags & ANOMALY_CONN_BURST_FL)
        return "CONN_BURST";
    if (flags & ANOMALY_HIGH_CONNS_FL)
        return "HIGH_CONNS";
    if (flags & ANOMALY_HIGH_BW_FL)
        return "HIGH_BW";
    return "MULTI";
}

/* ================================================================
 * HELPERS
 * ================================================================ */
static inline bool is_internal_dns(__be32 dst_ip, u16 dst_port)
{
    return (dst_port == 53 &&
            (dst_ip == htonl(0x7F000035) ||
             dst_ip == htonl(0x7F000001)));
}

static inline void make_canonical(__be32 *src_ip, u16 *src_port,
                                  __be32 *dst_ip, u16 *dst_port)
{
    if (ntohl(*src_ip) > ntohl(*dst_ip) ||
        (ntohl(*src_ip) == ntohl(*dst_ip) && *src_port > *dst_port))
    {
        __be32 tmp_ip = *src_ip;
        u16 tmp_port = *src_port;
        *src_ip = *dst_ip;
        *src_port = *dst_port;
        *dst_ip = tmp_ip;
        *dst_port = tmp_port;
    }
}

/* ================================================================
 * RATE TRACKING
 * ================================================================ */
struct rate_window
{
    u64 bytes_out_last;
    u64 bytes_in_last;
    u64 window_start;
    u32 rate_out_bps;
    u32 rate_in_bps;
};

/* ================================================================
 * TRAFFIC ENTRY
 * ================================================================ */
struct traffic_entry
{
    pid_t pid;
    uid_t uid;
    char comm[TASK_COMM_LEN];
    bool is_resolved;

    u8 protocol;
    bool is_dns;
    __be32 src_ip;
    __be32 dest_ip;
    u16 src_port;
    u16 dest_port;

    char domain[DOMAIN_NAME_MAX];

    u64 bytes_out;
    u64 bytes_in;
    u64 packets_out;
    u64 packets_in;

    struct rate_window rate;

    u64 first_seen;
    u64 last_seen;
    u64 closed_at;
    enum conn_state state;

    bool route_requested;

    /* PHASE 6: netlink update throttle */
    u64 nl_last_update;   /* timestamp of last CONN_UPDATE sent  */
    u32 nl_last_rate_out; /* rate at last update (for % change)  */
    u32 nl_last_rate_in;
};

struct traffic_node
{
    struct traffic_entry entry;
    struct list_head list;
};

/* ================================================================
 * TOP-N CONNECTION SNAPSHOT
 * ================================================================ */
struct top_conn
{
    __be32 remote_ip;
    u16 remote_port;
    u8 protocol;
    u64 total_bytes;
    u32 rate_bps;
    enum conn_state state;
    char domain[DOMAIN_NAME_MAX];
};

/* ================================================================
 * VELOCITY TRACKER
 * ================================================================ */
struct velocity
{
    u32 new_conns_this_sec;
    u32 new_conns_last_sec;
    u64 window_start;
    u16 dest_ports[ANOMALY_PORT_SCAN_PORTS * 2];
    u8 port_count;
};

/* ================================================================
 * PER-PROCESS ENTRY
 * ================================================================ */
struct proc_entry
{
    pid_t pid;
    uid_t uid;
    char comm[TASK_COMM_LEN];
    char exe[EXE_PATH_MAX];

    u32 tcp_conns;
    u32 udp_conns;
    u32 total_conns;
    u32 syn_pending;

    u64 bytes_out;
    u64 bytes_in;
    u64 packets_out;
    u64 packets_in;

    u32 rate_out_bps;
    u32 rate_in_bps;

    u8 tcp_pct;
    u8 udp_pct;

    u8 anomaly_flags;
    struct velocity vel;

    struct top_conn top[PROC_TOP_CONNS];
    u8 top_count;

    struct list_head list;
};

struct proc_node
{
    struct proc_entry entry;
    struct list_head list;
};

/* ================================================================
 * GLOBALS
 * ================================================================ */
extern struct list_head traffic_list;
extern struct list_head proc_list;
extern spinlock_t stats_lock;

/* ================================================================
 * FUNCTION DECLARATIONS
 * ================================================================ */
int net_hook_init(void);
void net_hook_cleanup(void);

int proc_fs_init(void);
void proc_fs_cleanup(void);

void stats_update(pid_t pid,
                  uid_t uid,
                  const char *comm,
                  const char *exe,
                  u8 protocol,
                  __be32 src_ip,
                  __be32 dest_ip,
                  u16 src_port,
                  u16 dest_port,
                  u64 bytes,
                  bool incoming,
                  bool is_resolved,
                  enum conn_state state,
                  bool is_new_conn);
void stats_cleanup(void);

void parse_packet(struct sk_buff *skb, bool incoming);

#endif /* _TRAFFIC_ANALYZER_H */