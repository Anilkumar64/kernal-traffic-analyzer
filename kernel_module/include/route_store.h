#ifndef _ROUTE_STORE_H
#define _ROUTE_STORE_H

#include <linux/types.h>
#include <linux/list.h>
#include <linux/hashtable.h>
#include <linux/seq_file.h>

/* ================================================================
 * TUNABLES
 * ================================================================ */
#define ROUTE_STORE_BITS 9 /* 512-bucket hash table          */
#define MAX_HOPS 32        /* maximum traceroute hops        */
#define HOP_HOST_MAX 64    /* hostname or IP string          */
#define ROUTE_TTL 600      /* seconds before route expires   */

/* ================================================================
 * SINGLE HOP
 *
 * Written by the userspace daemon after running traceroute.
 * Geo fields are populated by the daemon using MaxMind GeoLite2.
 * ================================================================ */
struct route_hop
{
    u8 hop_num;              /* 1-based                        */
    __be32 ip;               /* 0 if hop didn't respond (*)    */
    char host[HOP_HOST_MAX]; /* PTR record or IP string        */
    u32 rtt_us;              /* round-trip time microseconds   */

    /* Geo fields — filled by userspace daemon */
    char city[64];
    char country[64];
    char country_code[4]; /* "US", "IN", etc.               */
    s32 lat_e6;           /* latitude  × 1,000,000          */
    s32 lon_e6;           /* longitude × 1,000,000          */
    char asn[16];         /* "AS15169"                      */
    char org[64];         /* "Google LLC"                   */
};

/* ================================================================
 * ROUTE ENTRY — one per unique remote IP
 * ================================================================ */
struct route_entry
{
    __be32 dest_ip;   /* the remote end of the conn     */
    char domain[256]; /* domain name (from dns_map)     */

    struct route_hop hops[MAX_HOPS];
    u8 hop_count; /* number of valid hops           */

    u8 status;        /* ROUTE_STATUS_* below           */
    u64 last_updated; /* ktime_get_real_seconds()       */
    u64 requested_at; /* when daemon was asked to probe */

    struct hlist_node node;
};

/* Route status values */
#define ROUTE_STATUS_PENDING 0 /* requested, daemon not run yet  */
#define ROUTE_STATUS_RUNNING 1 /* daemon currently tracing       */
#define ROUTE_STATUS_DONE 2    /* hops populated                 */
#define ROUTE_STATUS_FAILED 3  /* traceroute failed              */

static inline const char *route_status_str(u8 s)
{
    switch (s)
    {
    case ROUTE_STATUS_PENDING:
        return "PENDING";
    case ROUTE_STATUS_RUNNING:
        return "RUNNING";
    case ROUTE_STATUS_DONE:
        return "DONE";
    case ROUTE_STATUS_FAILED:
        return "FAILED";
    default:
        return "UNKNOWN";
    }
}

/* ================================================================
 * API
 * ================================================================ */
void route_store_init(void);
void route_store_cleanup(void);

/*
 * route_store_request — mark an IP as needing a traceroute.
 * Called by stats.c when a new ESTABLISHED connection is seen.
 * Does nothing if a non-expired route already exists for this IP.
 */
void route_store_request(__be32 ip, const char *domain);

/*
 * route_store_write — called from proc write handler.
 * The userspace daemon writes completed route data here.
 * Format: see proc_interface.c write handler documentation.
 */
int route_store_write(const char *buf, size_t len);

/*
 * route_store_lookup — fill route_entry for display.
 * Returns true if an entry exists (any status).
 */
bool route_store_lookup(__be32 ip, struct route_entry *out);

/* Iteration for proc seq_file output */
void route_store_seq_show(struct seq_file *m);

/* Read pending requests — used by proc to expose work queue */
void route_store_pending_seq_show(struct seq_file *m);

#endif /* _ROUTE_STORE_H */