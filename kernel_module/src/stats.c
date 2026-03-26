#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/timekeeping.h>
#include <linux/in.h>
#include "../include/traffic_analyzer.h"
#include "../include/dns_map.h"
#include "../include/route_store.h"
#include "../include/netlink_comm.h" /* PHASE 6 */

/* ================================================================
 * GLOBALS
 * ================================================================ */
LIST_HEAD(traffic_list);
LIST_HEAD(proc_list);
DEFINE_SPINLOCK(stats_lock);

static unsigned int traffic_entries = 0;
static unsigned int proc_entries = 0;
static u64 last_cleanup = 0;

static struct
{
    pid_t pid;
    struct velocity vel;
} vel_save[MAX_PROC_ENTRIES];

/*
 * PHASE 6: Update throttle tracking.
 * We don't want to send a netlink CONN_UPDATE on every single packet
 * — that would flood subscribers on high-bandwidth connections.
 * Instead we send an update when:
 *   a) rate changed by more than UPDATE_RATE_THRESHOLD percent, OR
 *   b) UPDATE_MAX_INTERVAL seconds have elapsed since last update
 */
#define UPDATE_RATE_THRESHOLD 10 /* percent change to trigger update */
#define UPDATE_MAX_INTERVAL 5    /* seconds between forced updates   */

/* ================================================================
 * TTL PER STATE
 * ================================================================ */
static u64 entry_ttl(const struct traffic_entry *e)
{
    switch (e->state)
    {
    case CONN_STATE_SYN_SENT:
    case CONN_STATE_SYN_RECV:
        return CONN_TTL_SYN;
    case CONN_STATE_CLOSED:
        return CONN_TTL_CLOSED;
    case CONN_STATE_FIN_WAIT:
        return CONN_TTL_FIN_WAIT;
    case CONN_STATE_UDP_ACTIVE:
        return CONN_TTL_UDP;
    case CONN_STATE_ESTABLISHED:
    default:
        return CONN_TTL_ACTIVE;
    }
    return CONN_TTL_ACTIVE;
}

/* ================================================================
 * STATE MACHINE
 * ================================================================ */
static void advance_state(struct traffic_entry *e,
                          enum conn_state new_state,
                          bool incoming)
{
    u64 now = ktime_get_real_seconds();

    if (new_state == CONN_STATE_CLOSED)
    {
        if (e->state != CONN_STATE_CLOSED)
            e->closed_at = now;
        e->state = CONN_STATE_CLOSED;
        return;
    }

    switch (e->state)
    {
    case CONN_STATE_SYN_SENT:
        if (new_state == CONN_STATE_ESTABLISHED && incoming)
            e->state = CONN_STATE_ESTABLISHED;
        break;
    case CONN_STATE_SYN_RECV:
        if (new_state == CONN_STATE_ESTABLISHED && !incoming)
            e->state = CONN_STATE_ESTABLISHED;
        break;
    case CONN_STATE_ESTABLISHED:
        if (new_state == CONN_STATE_FIN_WAIT)
            e->state = CONN_STATE_FIN_WAIT;
        break;
    case CONN_STATE_FIN_WAIT:
        if (new_state == CONN_STATE_ESTABLISHED ||
            new_state == CONN_STATE_FIN_WAIT)
        {
            e->state = CONN_STATE_CLOSED;
            e->closed_at = now;
        }
        break;
    case CONN_STATE_CLOSED:
    case CONN_STATE_UDP_ACTIVE:
        break;
    }
}

/* ================================================================
 * RATE WINDOW
 * ================================================================ */
static void update_rate(struct traffic_entry *e, u64 now)
{
    struct rate_window *r = &e->rate;
    u64 elapsed = now - r->window_start;

    if (elapsed >= RATE_WINDOW_SECS)
    {
        u64 out_delta = e->bytes_out - r->bytes_out_last;
        u64 in_delta = e->bytes_in - r->bytes_in_last;

        if (elapsed > 0)
        {
            r->rate_out_bps = (u32)(out_delta / elapsed);
            r->rate_in_bps = (u32)(in_delta / elapsed);
        }

        r->bytes_out_last = e->bytes_out;
        r->bytes_in_last = e->bytes_in;
        r->window_start = now;
    }
}

/* ================================================================
 * PHASE 6: SHOULD SEND UPDATE?
 *
 * Returns true if the connection state warrants a CONN_UPDATE
 * netlink message.  Throttles by rate change % and time elapsed.
 * ================================================================ */
static bool should_send_update(struct traffic_entry *e, u64 now)
{
    u32 old_rate = e->nl_last_rate_out + e->nl_last_rate_in;
    u32 new_rate = e->rate.rate_out_bps + e->rate.rate_in_bps;
    u64 elapsed = now - e->nl_last_update;

    /* Force update every UPDATE_MAX_INTERVAL seconds */
    if (elapsed >= UPDATE_MAX_INTERVAL)
        return true;

    /* Skip if no traffic at all */
    if (old_rate == 0 && new_rate == 0)
        return false;

    /* Send if rate changed by more than threshold */
    if (old_rate == 0)
        return new_rate > 0;

    u32 change_pct = (u32)(abs((s64)new_rate - (s64)old_rate) * 100 / old_rate);
    return change_pct >= UPDATE_RATE_THRESHOLD;
}

/* ================================================================
 * VELOCITY TRACKER
 * ================================================================ */
static void velocity_record_new_conn(struct proc_entry *pe,
                                     __be32 dest_ip,
                                     u16 dest_port,
                                     u64 now)
{
    struct velocity *v = &pe->vel;
    bool port_known = false;
    int i;

    if (now != v->window_start)
    {
        v->new_conns_last_sec = v->new_conns_this_sec;
        v->new_conns_this_sec = 0;
        v->port_count = 0;
        v->window_start = now;
    }

    v->new_conns_this_sec++;

    for (i = 0; i < v->port_count; i++)
    {
        if (v->dest_ports[i] == dest_port)
        {
            port_known = true;
            break;
        }
    }

    if (!port_known && v->port_count < ARRAY_SIZE(v->dest_ports))
        v->dest_ports[v->port_count++] = dest_port;
}

/* ================================================================
 * ANOMALY DETECTION
 * ================================================================ */
static bool is_system_process(const char *comm)
{
    /* Whitelist known system tools that generate high SYN counts */
    return (strncmp(comm, "traceroute", 10) == 0 ||
            strncmp(comm, "ping",       4)  == 0 ||
            strncmp(comm, "nmap",       4)  == 0 ||
            strncmp(comm, "curl",       4)  == 0 ||
            strncmp(comm, "wget",       4)  == 0);
}

static u8 detect_anomalies(const struct proc_entry *pe)
{
    u8 flags = ANOMALY_NONE;

    if (pe->vel.new_conns_last_sec >= ANOMALY_CONN_BURST)
        flags |= ANOMALY_CONN_BURST_FL;
    if (pe->vel.port_count >= ANOMALY_PORT_SCAN_PORTS)
        flags |= ANOMALY_PORT_SCAN_FL;
    if (pe->total_conns >= ANOMALY_MAX_CONNS)
        flags |= ANOMALY_HIGH_CONNS_FL;
    if (pe->tcp_conns > 0 && !is_system_process(pe->comm))
    {
        u32 syn_pct = (pe->syn_pending * 100) / pe->tcp_conns;
        if (syn_pct >= ANOMALY_SYN_RATIO)
            flags |= ANOMALY_SYN_FLOOD_FL;
    }
    if ((pe->rate_out_bps + pe->rate_in_bps) > (10 * 1024 * 1024))
        flags |= ANOMALY_HIGH_BW_FL;

    return flags;
}

/* ================================================================
 * TOP-N UPDATE
 * ================================================================ */
static void update_top_conns(struct proc_entry *pe,
                             const struct traffic_entry *te,
                             __be32 local_ip)
{
    u64 total = te->bytes_out + te->bytes_in;
    u32 rate = te->rate.rate_out_bps + te->rate.rate_in_bps;
    __be32 remote_ip = (te->src_ip == local_ip) ? te->dest_ip : te->src_ip;
    u16 remote_port = (te->src_ip == local_ip) ? te->dest_port : te->src_port;
    int i;

    for (i = 0; i < pe->top_count; i++)
    {
        if (pe->top[i].remote_ip == remote_ip &&
            pe->top[i].remote_port == remote_port &&
            pe->top[i].protocol == te->protocol)
        {
            pe->top[i].total_bytes = total;
            pe->top[i].rate_bps = rate;
            pe->top[i].state = te->state;
            if (te->domain[0] && !pe->top[i].domain[0])
                strscpy(pe->top[i].domain, te->domain, DOMAIN_NAME_MAX);
            return;
        }
    }

    if (pe->top_count < PROC_TOP_CONNS)
    {
        pe->top[pe->top_count].remote_ip = remote_ip;
        pe->top[pe->top_count].remote_port = remote_port;
        pe->top[pe->top_count].protocol = te->protocol;
        pe->top[pe->top_count].total_bytes = total;
        pe->top[pe->top_count].rate_bps = rate;
        pe->top[pe->top_count].state = te->state;
        strscpy(pe->top[pe->top_count].domain,
                te->domain[0] ? te->domain : "", DOMAIN_NAME_MAX);
        pe->top_count++;
        return;
    }

    {
        int min_idx = 0;
        u64 min_bytes = pe->top[0].total_bytes;
        for (i = 1; i < PROC_TOP_CONNS; i++)
        {
            if (pe->top[i].total_bytes < min_bytes)
            {
                min_bytes = pe->top[i].total_bytes;
                min_idx = i;
            }
        }
        if (total > min_bytes)
        {
            pe->top[min_idx].remote_ip = remote_ip;
            pe->top[min_idx].remote_port = remote_port;
            pe->top[min_idx].protocol = te->protocol;
            pe->top[min_idx].total_bytes = total;
            pe->top[min_idx].rate_bps = rate;
            pe->top[min_idx].state = te->state;
            strscpy(pe->top[min_idx].domain,
                    te->domain[0] ? te->domain : "", DOMAIN_NAME_MAX);
        }
    }
}

/* ================================================================
 * REBUILD PROC LIST
 * ================================================================ */
static void rebuild_proc_list_locked(u64 now)
{
    struct traffic_node *tnode;
    struct proc_node *pnode, *ptmp;
    int vel_count = 0, i;

    list_for_each_entry(pnode, &proc_list, list)
    {
        if (vel_count < MAX_PROC_ENTRIES)
        {
            vel_save[vel_count].pid = pnode->entry.pid;
            vel_save[vel_count].vel = pnode->entry.vel;
            vel_count++;
        }
    }

    list_for_each_entry_safe(pnode, ptmp, &proc_list, list)
    {
        list_del(&pnode->list);
        kfree(pnode);
    }
    proc_entries = 0;

    list_for_each_entry(tnode, &traffic_list, list)
    {
        struct traffic_entry *te = &tnode->entry;
        struct proc_entry *pe = NULL;
        bool found = false;

        if (te->state == CONN_STATE_CLOSED || te->is_dns)
            continue;

        list_for_each_entry(pnode, &proc_list, list)
        {
            if (pnode->entry.pid == te->pid)
            {
                pe = &pnode->entry;
                found = true;
                break;
            }
        }

        if (!found)
        {
            if (proc_entries >= MAX_PROC_ENTRIES)
                continue;

            pnode = kmalloc(sizeof(*pnode), GFP_ATOMIC);
            if (!pnode)
                continue;

            memset(pnode, 0, sizeof(*pnode));
            pnode->entry.pid = te->pid;
            pnode->entry.uid = te->uid;
            strscpy(pnode->entry.comm, te->comm, TASK_COMM_LEN);

            for (i = 0; i < vel_count; i++)
            {
                if (vel_save[i].pid == te->pid)
                {
                    pnode->entry.vel = vel_save[i].vel;
                    break;
                }
            }

            INIT_LIST_HEAD(&pnode->list);
            list_add_tail(&pnode->list, &proc_list);
            proc_entries++;
            pe = &pnode->entry;
        }

        pe->bytes_out += te->bytes_out;
        pe->bytes_in += te->bytes_in;
        pe->packets_out += te->packets_out;
        pe->packets_in += te->packets_in;
        pe->rate_out_bps += te->rate.rate_out_bps;
        pe->rate_in_bps += te->rate.rate_in_bps;
        pe->total_conns++;

        if (te->protocol == IPPROTO_TCP)
        {
            pe->tcp_conns++;
            if (te->state == CONN_STATE_SYN_SENT ||
                te->state == CONN_STATE_SYN_RECV)
                pe->syn_pending++;
        }
        else
        {
            pe->udp_conns++;
        }

        update_top_conns(pe, te, te->src_ip);
    }

    list_for_each_entry(pnode, &proc_list, list)
    {
        struct proc_entry *pe = &pnode->entry;
        u8 old_flags = pe->anomaly_flags;

        if (pe->total_conns > 0)
        {
            pe->tcp_pct = (u8)((pe->tcp_conns * 100) / pe->total_conns);
            pe->udp_pct = (u8)((pe->udp_conns * 100) / pe->total_conns);
        }

        pe->anomaly_flags = detect_anomalies(pe);

        /*
         * PHASE 6: Emit anomaly netlink event when flags change.
         * Drop stats_lock briefly — ta_nl_send_anomaly is GFP_ATOMIC.
         * We can do this because we hold spin_lock_bh which prevents
         * re-entry from the same CPU's softirq.
         */
        if (pe->anomaly_flags != ANOMALY_NONE &&
            pe->anomaly_flags != old_flags)
        {
            ta_nl_send_anomaly(pe);
        }
    }
}

/* ================================================================
 * STATS UPDATE
 * ================================================================ */
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
                  bool is_new_conn)
{
    struct traffic_node *node;
    u64 now = ktime_get_real_seconds();
    bool dns_flag = is_internal_dns(dest_ip, dest_port) ||
                    is_internal_dns(src_ip, src_port);

    __be32 remote_ip = incoming ? src_ip : dest_ip;

    __be32 c_src_ip = src_ip;
    __be32 c_dst_ip = dest_ip;
    u16 c_src_port = src_port;
    u16 c_dst_port = dest_port;
    make_canonical(&c_src_ip, &c_src_port, &c_dst_ip, &c_dst_port);

    spin_lock_bh(&stats_lock);

    if (now - last_cleanup >= 1)
    {
        struct traffic_node *tmp;

        list_for_each_entry_safe(node, tmp, &traffic_list, list)
        {
            if (now - node->entry.last_seen > entry_ttl(&node->entry))
            {
                /*
                 * PHASE 6: Emit CONN_CLOSED before freeing.
                 * The entry is still valid at this point.
                 */
                if (node->entry.state != CONN_STATE_CLOSED)
                    ta_nl_send_conn_closed(&node->entry);

                list_del(&node->list);
                kfree(node);
                traffic_entries--;
            }
        }

        rebuild_proc_list_locked(now);
        last_cleanup = now;
    }

    /* Match existing entry */
    list_for_each_entry(node, &traffic_list, list)
    {
        struct traffic_entry *e = &node->entry;

        if (e->protocol != protocol ||
            e->src_ip != c_src_ip ||
            e->dest_ip != c_dst_ip ||
            e->src_port != c_src_port ||
            e->dest_port != c_dst_port)
            continue;

        if (incoming)
        {
            e->bytes_in += bytes;
            e->packets_in++;
        }
        else
        {
            e->bytes_out += bytes;
            e->packets_out++;
        }
        e->last_seen = now;

        update_rate(e, now);

        enum conn_state old_state = e->state;
        advance_state(e, state, incoming);

        if (is_resolved && !e->is_resolved)
        {
            e->pid = pid;
            e->uid = uid;
            e->is_resolved = true;
            strscpy(e->comm, comm, TASK_COMM_LEN);
        }

        if (!e->domain[0])
            dns_map_lookup(c_dst_ip, e->domain, DOMAIN_NAME_MAX);

        /* Route request */
        if (!e->route_requested && !e->is_dns && protocol == IPPROTO_TCP)
        {
            e->route_requested = true;
            route_store_request(remote_ip,
                                e->domain[0] ? e->domain : NULL);
        }

        /*
         * PHASE 6: Emit netlink events on state transitions.
         *
         * CONN_CLOSED: emitted immediately when state changes to
         *              CLOSED so GUI can update instantly.
         *
         * CONN_UPDATE: throttled — only when rate changed
         *              significantly or interval elapsed.
         */
        if (e->state == CONN_STATE_CLOSED &&
            old_state != CONN_STATE_CLOSED)
        {
            ta_nl_send_conn_closed(e);
        }
        else if (should_send_update(e, now))
        {
            e->nl_last_rate_out = e->rate.rate_out_bps;
            e->nl_last_rate_in = e->rate.rate_in_bps;
            e->nl_last_update = now;
            ta_nl_send_conn_update(e);
        }

        if (is_new_conn && !dns_flag)
        {
            struct proc_node *pnode;
            list_for_each_entry(pnode, &proc_list, list)
            {
                if (pnode->entry.pid == pid)
                {
                    velocity_record_new_conn(&pnode->entry,
                                             c_dst_ip, c_dst_port, now);
                    break;
                }
            }
        }

        spin_unlock_bh(&stats_lock);
        return;
    }

    /* New entry */
    if (state == CONN_STATE_CLOSED)
        goto out_unlock;

    if (traffic_entries >= MAX_TRAFFIC_ENTRIES)
    {
        struct traffic_node *oldest =
            list_first_entry(&traffic_list, struct traffic_node, list);
        ta_nl_send_conn_closed(&oldest->entry);
        list_del(&oldest->list);
        kfree(oldest);
        traffic_entries--;
    }

    node = kmalloc(sizeof(*node), GFP_ATOMIC);
    if (!node)
        goto out_unlock;

    memset(node, 0, sizeof(*node));

    node->entry.pid = pid;
    node->entry.uid = uid;
    strscpy(node->entry.comm, comm, TASK_COMM_LEN);
    node->entry.protocol = protocol;
    node->entry.is_resolved = is_resolved;
    node->entry.is_dns = dns_flag;
    node->entry.state = state;
    node->entry.src_ip = c_src_ip;
    node->entry.dest_ip = c_dst_ip;
    node->entry.src_port = c_src_port;
    node->entry.dest_port = c_dst_port;
    node->entry.route_requested = false;
    node->entry.nl_last_update = now;

    dns_map_lookup(c_dst_ip, node->entry.domain, DOMAIN_NAME_MAX);

    if (incoming)
    {
        node->entry.bytes_in = bytes;
        node->entry.packets_in = 1;
    }
    else
    {
        node->entry.bytes_out = bytes;
        node->entry.packets_out = 1;
    }

    node->entry.first_seen = now;
    node->entry.last_seen = now;
    node->entry.rate.window_start = now;

    INIT_LIST_HEAD(&node->list);
    list_add_tail(&node->list, &traffic_list);
    traffic_entries++;

    /* PHASE 6: Emit CONN_NEW immediately */
    ta_nl_send_conn_new(&node->entry);

    /* Route request */
    if (!dns_flag && protocol == IPPROTO_TCP)
    {
        node->entry.route_requested = true;
        route_store_request(remote_ip,
                            node->entry.domain[0]
                                ? node->entry.domain
                                : NULL);
    }

    if (!dns_flag)
    {
        struct proc_node *pnode;
        list_for_each_entry(pnode, &proc_list, list)
        {
            if (pnode->entry.pid == pid)
            {
                velocity_record_new_conn(&pnode->entry,
                                         c_dst_ip, c_dst_port, now);
                if (exe && exe[0] && !pnode->entry.exe[0])
                    strscpy(pnode->entry.exe, exe, EXE_PATH_MAX);
                break;
            }
        }
    }

out_unlock:
    spin_unlock_bh(&stats_lock);
}

/* ================================================================
 * CLEANUP
 * ================================================================ */
void stats_cleanup(void)
{
    struct traffic_node *tnode, *ttmp;
    struct proc_node *pnode, *ptmp;

    spin_lock_bh(&stats_lock);

    list_for_each_entry_safe(tnode, ttmp, &traffic_list, list)
    {
        list_del(&tnode->list);
        kfree(tnode);
    }
    traffic_entries = 0;

    list_for_each_entry_safe(pnode, ptmp, &proc_list, list)
    {
        list_del(&pnode->list);
        kfree(pnode);
    }
    proc_entries = 0;

    spin_unlock_bh(&stats_lock);
}