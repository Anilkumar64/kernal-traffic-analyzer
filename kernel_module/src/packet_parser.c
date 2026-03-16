#include <linux/kernel.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/skbuff.h>
#include <linux/sched.h>
#include <net/sock.h>

#include "../include/traffic_analyzer.h"

void parse_packet(struct sk_buff *skb)
{
    struct iphdr *ip;
    struct tcphdr *tcp;
    struct udphdr *udp;
    struct sock *sk;

    u16 dest_port = 0;

    if (!skb)
        return;

    /* ensure IP header is accessible */
    if (!pskb_may_pull(skb, sizeof(struct iphdr)))
        return;

    ip = ip_hdr(skb);
    if (!ip)
        return;

    /* only track TCP/UDP */
    if (ip->protocol != IPPROTO_TCP && ip->protocol != IPPROTO_UDP)
        return;

    /* extract destination port */
    if (ip->protocol == IPPROTO_TCP)
    {
        tcp = tcp_hdr(skb);
        dest_port = ntohs(tcp->dest);
    }
    else if (ip->protocol == IPPROTO_UDP)
    {
        udp = udp_hdr(skb);
        dest_port = ntohs(udp->dest);
    }

    /* ignore packets without socket context */
    sk = skb->sk;
    if (!sk)
        return;

    /* ignore kernel threads */
    if (task_pid_nr(current) == 0)
        return;

    /* update statistics */
    stats_update(
        task_pid_nr(current),
        current->comm,
        ip->daddr,
        dest_port,
        skb->len);
}