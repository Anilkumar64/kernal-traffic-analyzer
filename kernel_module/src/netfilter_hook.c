#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_ipv6.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/udp.h>
#include <net/ip.h>
#include "../include/traffic_analyzer.h"
#include "../include/dns_parser.h"
#include "../include/flow_cache.h"
#include "../include/sock_cache.h"

static struct nf_hook_ops nfho_out;
static struct nf_hook_ops nfho_in;
static struct nf_hook_ops nfho6_out;
static struct nf_hook_ops nfho6_in;

static inline bool is_valid_ipv4(struct sk_buff *skb)
{
    return skb &&
           pskb_may_pull(skb, sizeof(struct iphdr)) &&
           ip_hdr(skb) != NULL;
}

static inline bool is_supported_proto(__u8 proto)
{
    return proto == IPPROTO_TCP || proto == IPPROTO_UDP;
}

/*
 * is_dns_response — true if this is a UDP packet from port 53.
 *
 * We intercept DNS RESPONSES (src_port == 53) not queries,
 * because responses contain the A records we need.
 */
static inline bool is_dns_response(struct sk_buff *skb)
{
    struct iphdr *ip;
    struct udphdr *udp;
    u8 dns_buf[12];
    u8 *dns_hdr;
    int udp_off;
    int udp_payload_off;

    if (!pskb_may_pull(skb, sizeof(struct iphdr) + sizeof(struct udphdr)))
        return false;

    ip = ip_hdr(skb);
    if (ip->protocol != IPPROTO_UDP)
        return false;

    udp_off = ip_hdrlen(skb);
    if (!pskb_may_pull(skb, udp_off + sizeof(struct udphdr)))
        return false;

    ip = ip_hdr(skb);
    udp = (struct udphdr *)((__u8 *)ip + udp_off);
    if (ntohs(udp->source) != 53)
        return false;

    udp_payload_off = udp_off + sizeof(struct udphdr);
    if (!pskb_may_pull(skb, udp_payload_off + 12))
        return false;

    dns_hdr = skb_header_pointer(skb, udp_payload_off, 12, dns_buf);
    if (!dns_hdr)
        return false;

    return (dns_hdr[2] & 0x80) != 0;
}

/*
 * resolve_pid_for_hook — lightweight PID lookup from sock cache only.
 * Used to attribute DNS queries to the right process without doing
 * a full scan (too expensive in hook context).
 */
static pid_t resolve_pid_for_hook(struct sk_buff *skb)
{
    struct sock *sk = skb_to_full_sk(skb);
    if (!sk)
        return 0;
    return sock_cache_lookup(sk);
}

/* ================================================================
 * OUTGOING HOOK
 * ================================================================ */
static unsigned int packet_out_hook(void *priv,
                                    struct sk_buff *skb,
                                    const struct nf_hook_state *state)
{
    if (!is_valid_ipv4(skb))
        return NF_ACCEPT;

    if (!is_supported_proto(ip_hdr(skb)->protocol))
        return NF_ACCEPT;

    parse_packet(skb, false);
    return NF_ACCEPT;
}

static unsigned int packet6_out_hook(void *priv,
                                     struct sk_buff *skb,
                                     const struct nf_hook_state *state)
{
    if (skb)
        parse_packet(skb, false);
    return NF_ACCEPT;
}

/* ================================================================
 * INCOMING HOOK
 *
 * Before passing to parse_packet, check if this is a DNS response.
 * If so, parse it and extract A records into dns_map before updating
 * traffic stats, so stats_update can use the cached domain name.
 * ================================================================ */
static unsigned int packet_in_hook(void *priv,
                                   struct sk_buff *skb,
                                   const struct nf_hook_state *state)
{
    if (!is_valid_ipv4(skb))
        return NF_ACCEPT;

    if (!is_supported_proto(ip_hdr(skb)->protocol))
        return NF_ACCEPT;

    /*
     * Intercept DNS responses arriving from port 53. Parse the DNS
     * payload first, populate dns_map with IP-to-domain mappings,
     * then let parse_packet handle stats.
     *
     * The PID we pass to parse_dns_response is the process that
     * owns the destination socket (the one that sent the query).
     * For systemd-resolved proxying, pid will be the resolver —
     * that's acceptable and still useful.
     */
    if (is_dns_response(skb))
    {
        pid_t pid = resolve_pid_for_hook(skb);
        char comm[TASK_COMM_LEN] = {0};

        if (pid > 0)
        {
            struct pid *p;
            struct task_struct *t;

            rcu_read_lock();
            p = find_get_pid(pid);
            if (p)
            {
                t = pid_task(p, PIDTYPE_PID);
                if (t)
                    get_task_comm(comm, t);
                put_pid(p);
            }
            rcu_read_unlock();
        }

        parse_dns_response(skb, pid, comm);
        /* Fall through — also record as a normal UDP packet */
    }

    parse_packet(skb, true);
    return NF_ACCEPT;
}

static unsigned int packet6_in_hook(void *priv,
                                    struct sk_buff *skb,
                                    const struct nf_hook_state *state)
{
    if (skb)
        parse_packet(skb, true);
    return NF_ACCEPT;
}

/* ================================================================
 * INIT / CLEANUP
 * ================================================================ */
int net_hook_init(void)
{
    int ret;

    nfho_out.hook = packet_out_hook;
    nfho_out.pf = PF_INET;
    nfho_out.hooknum = NF_INET_LOCAL_OUT;
    nfho_out.priority = NF_IP_PRI_FIRST;

    ret = nf_register_net_hook(&init_net, &nfho_out);
    if (ret)
    {
        printk(KERN_ERR "[TA] Failed to register LOCAL_OUT hook\n");
        return ret;
    }

    nfho_in.hook = packet_in_hook;
    nfho_in.pf = PF_INET;
    nfho_in.hooknum = NF_INET_LOCAL_IN;
    nfho_in.priority = NF_IP_PRI_FIRST;

    ret = nf_register_net_hook(&init_net, &nfho_in);
    if (ret)
    {
        printk(KERN_ERR "[TA] Failed to register LOCAL_IN hook\n");
        nf_unregister_net_hook(&init_net, &nfho_out);
        return ret;
    }

    nfho6_out.hook = packet6_out_hook;
    nfho6_out.pf = NFPROTO_IPV6;
    nfho6_out.hooknum = NF_INET_LOCAL_OUT;
    nfho6_out.priority = NF_IP6_PRI_FIRST;

    ret = nf_register_net_hook(&init_net, &nfho6_out);
    if (ret)
    {
        printk(KERN_ERR "[TA] Failed to register IPv6 LOCAL_OUT hook\n");
        nf_unregister_net_hook(&init_net, &nfho_in);
        nf_unregister_net_hook(&init_net, &nfho_out);
        return ret;
    }

    nfho6_in.hook = packet6_in_hook;
    nfho6_in.pf = NFPROTO_IPV6;
    nfho6_in.hooknum = NF_INET_LOCAL_IN;
    nfho6_in.priority = NF_IP6_PRI_FIRST;

    ret = nf_register_net_hook(&init_net, &nfho6_in);
    if (ret)
    {
        printk(KERN_ERR "[TA] Failed to register IPv6 LOCAL_IN hook\n");
        nf_unregister_net_hook(&init_net, &nfho6_out);
        nf_unregister_net_hook(&init_net, &nfho_in);
        nf_unregister_net_hook(&init_net, &nfho_out);
        return ret;
    }

    printk(KERN_INFO "[traffic_analyzer] Netfilter hooks registered (IPv4/IPv6 LOCAL_IN/OUT)\n");
    return 0;
}

void net_hook_cleanup(void)
{
    nf_unregister_net_hook(&init_net, &nfho6_in);
    nf_unregister_net_hook(&init_net, &nfho6_out);
    nf_unregister_net_hook(&init_net, &nfho_out);
    nf_unregister_net_hook(&init_net, &nfho_in);
    printk(KERN_INFO "[traffic_analyzer] Netfilter hooks removed\n");
}
