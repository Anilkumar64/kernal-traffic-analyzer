#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netlink.h>
#include <linux/skbuff.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <net/sock.h>
#include <net/netlink.h>
#include "../include/netlink_comm.h"
#include "../include/traffic_analyzer.h"
#include "../include/route_store.h"

static struct sock *ta_nl_sock = NULL;

/* ================================================================
 * INIT / CLEANUP
 * ================================================================ */
int ta_netlink_init(void)
{
    struct netlink_kernel_cfg cfg = {
        .groups = 32,
        .flags = NL_CFG_F_NONROOT_RECV | NL_CFG_F_NONROOT_SEND,
        .input = NULL,
    };

    ta_nl_sock = netlink_kernel_create(&init_net, TA_NETLINK_PROTO, &cfg);
    if (!ta_nl_sock)
    {
        printk(KERN_ERR "[TA] Failed to create netlink socket\n");
        return -ENOMEM;
    }

    printk(KERN_INFO "[TA] Netlink socket created (proto=%d)\n",
           TA_NETLINK_PROTO);
    return 0;
}

void ta_netlink_cleanup(void)
{
    if (ta_nl_sock)
    {
        netlink_kernel_release(ta_nl_sock);
        ta_nl_sock = NULL;
    }
}

/* ================================================================
 * MULTICAST SEND HELPER
 *
 * Called from softirq context — must use GFP_ATOMIC.
 * ================================================================ */
static void ta_nl_multicast(const void *payload, size_t payload_len,
                            int group)
{
    struct sk_buff *skb;
    struct nlmsghdr *nlh;

    if (!ta_nl_sock)
        return;

    skb = nlmsg_new(payload_len, GFP_ATOMIC);
    if (!skb)
        return;

    nlh = nlmsg_put(skb, 0, 0, 0, payload_len, 0);
    if (!nlh)
    {
        kfree_skb(skb);
        return;
    }

    memcpy(nlmsg_data(nlh), payload, payload_len);
    nlmsg_multicast(ta_nl_sock, skb, 0, group, GFP_ATOMIC);
}

/* ================================================================
 * FILL HEADER
 * ================================================================ */
static void fill_hdr(struct ta_msg_hdr *hdr, u32 type, u32 len)
{
    hdr->type = type;
    hdr->len = len;
    hdr->timestamp = ktime_get_real_seconds();
}

/* ================================================================
 * FILL CONN MESSAGE
 * ================================================================ */
static void fill_conn_msg(struct ta_msg_conn *msg,
                          u32 type,
                          const struct traffic_entry *e)
{
    memset(msg, 0, sizeof(*msg));
    fill_hdr(&msg->hdr, type, sizeof(*msg));

    msg->pid = e->pid;
    msg->uid = e->uid;
    strscpy(msg->comm, e->comm,
            sizeof(msg->comm));
    strscpy(msg->domain, e->domain[0] ? e->domain : "-",
            sizeof(msg->domain));

    msg->protocol = e->protocol;
    msg->state = (u8)e->state;
    msg->is_dns = e->is_dns ? 1 : 0;
    msg->is_resolved = e->is_resolved ? 1 : 0;

    msg->src_ip = e->src_ip;
    msg->dest_ip = e->dest_ip;
    msg->src_port = e->src_port;
    msg->dest_port = e->dest_port;

    msg->bytes_out = e->bytes_out;
    msg->bytes_in = e->bytes_in;
    msg->packets_out = e->packets_out;
    msg->packets_in = e->packets_in;

    msg->rate_out_bps = e->rate.rate_out_bps;
    msg->rate_in_bps = e->rate.rate_in_bps;

    msg->first_seen = e->first_seen;
    msg->last_seen = e->last_seen;
    msg->closed_at = e->closed_at;
}

/* ================================================================
 * PUBLIC SEND FUNCTIONS
 * ================================================================ */

void ta_nl_send_conn_new(const struct traffic_entry *e)
{
    struct ta_msg_conn msg;
    fill_conn_msg(&msg, TA_MSG_CONN_NEW, e);
    ta_nl_multicast(&msg, sizeof(msg), TA_GROUP_CONNECTIONS);
}

void ta_nl_send_conn_update(const struct traffic_entry *e)
{
    struct ta_msg_conn msg;
    fill_conn_msg(&msg, TA_MSG_CONN_UPDATE, e);
    ta_nl_multicast(&msg, sizeof(msg), TA_GROUP_CONNECTIONS);
}

void ta_nl_send_conn_closed(const struct traffic_entry *e)
{
    struct ta_msg_conn msg;
    fill_conn_msg(&msg, TA_MSG_CONN_CLOSED, e);
    ta_nl_multicast(&msg, sizeof(msg), TA_GROUP_CONNECTIONS);
}

void ta_nl_send_anomaly(const struct proc_entry *e)
{
    struct ta_msg_anomaly msg;

    memset(&msg, 0, sizeof(msg));
    fill_hdr(&msg.hdr, TA_MSG_ANOMALY, sizeof(msg));

    msg.pid = e->pid;
    msg.uid = e->uid;
    strscpy(msg.comm, e->comm, sizeof(msg.comm));
    strscpy(msg.exe, e->exe[0] ? e->exe : "-", sizeof(msg.exe));

    msg.anomaly_flags = e->anomaly_flags;
    msg.total_conns = e->total_conns;
    msg.syn_pending = e->syn_pending;
    msg.new_conns_last_sec = e->vel.new_conns_last_sec;
    msg.unique_ports_last_sec = e->vel.port_count;
    msg.rate_out_bps = e->rate_out_bps;
    msg.rate_in_bps = e->rate_in_bps;

    ta_nl_multicast(&msg, sizeof(msg), TA_GROUP_ANOMALIES);
}

void ta_nl_send_dns(__be32 ip, const char *domain,
                    u32 ttl, pid_t pid, const char *comm)
{
    struct ta_msg_dns msg;

    memset(&msg, 0, sizeof(msg));
    fill_hdr(&msg.hdr, TA_MSG_DNS_RESOLVED, sizeof(msg));

    msg.ip = ip;
    msg.ttl = ttl;
    msg.queried_by_pid = pid;
    strscpy(msg.domain, domain ? domain : "-", sizeof(msg.domain));
    strscpy(msg.queried_by_comm, comm ? comm : "-", sizeof(msg.queried_by_comm));

    ta_nl_multicast(&msg, sizeof(msg), TA_GROUP_DNS);
}

/*
 * ta_nl_send_route — send a completed route to userspace subscribers.
 *
 * FIX: struct ta_msg_route is ~9776 bytes (TA_MAX_HOPS hops × large
 * string fields).  Putting it on the kernel stack overflows the 1024-
 * byte frame limit and risks a stack overflow / kernel panic.
 *
 * Solution: allocate on the heap with GFP_ATOMIC (safe from softirq),
 * fill it, multicast, then free.
 */
void ta_nl_send_route(const struct route_entry *e)
{
    struct ta_msg_route *msg;
    int i;

    /* Heap allocation — avoids the 9776-byte stack frame */
    msg = kmalloc(sizeof(*msg), GFP_ATOMIC);
    if (!msg)
        return;

    memset(msg, 0, sizeof(*msg));
    fill_hdr(&msg->hdr, TA_MSG_ROUTE_READY, sizeof(*msg));

    msg->dest_ip = e->dest_ip;
    msg->hop_count = e->hop_count;
    strscpy(msg->domain, e->domain[0] ? e->domain : "-",
            sizeof(msg->domain));

    for (i = 0; i < e->hop_count && i < TA_MAX_HOPS; i++)
    {
        const struct route_hop *src = &e->hops[i];
        struct ta_route_hop_msg *dst = &msg->hops[i];
        dst->hop_num = src->hop_num;
        dst->ip = src->ip;
        dst->rtt_us = src->rtt_us;
        dst->lat_e6 = src->lat_e6;
        dst->lon_e6 = src->lon_e6;

        strscpy(dst->host, src->host[0] ? src->host : "-", sizeof(dst->host));
        strscpy(dst->city, src->city[0] ? src->city : "-", sizeof(dst->city));
        strscpy(dst->country, src->country[0] ? src->country : "-", sizeof(dst->country));
        strscpy(dst->country_code, src->country_code[0] ? src->country_code : "-", sizeof(dst->country_code));
        strscpy(dst->asn, src->asn[0] ? src->asn : "-", sizeof(dst->asn));
        strscpy(dst->org, src->org[0] ? src->org : "-", sizeof(dst->org));
    }

    ta_nl_multicast(msg, sizeof(*msg), TA_GROUP_ROUTES);
    kfree(msg);
}