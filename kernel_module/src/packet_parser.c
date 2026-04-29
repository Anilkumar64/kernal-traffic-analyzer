#include <linux/kernel.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/skbuff.h>
#include <linux/sched.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/pid.h>
#include <net/ip.h>
#include <net/ipv6.h>
#include <net/sock.h>
#include <linux/sched/signal.h>
#include <linux/fdtable.h>
#include <linux/rcupdate.h>
#include "../include/traffic_analyzer.h"
#include "../include/resolver.h"
#include "../include/sock_cache.h"
#include "../include/flow_cache.h"
#include "../include/inode_cache.h"
#include "../include/cache.h"
#include "../include/exe_resolver.h"

/* ================================================================
 * HELPERS
 * ================================================================ */
static inline bool is_kernel_thread(const char *comm)
{
    return (strncmp(comm, "ksoftirqd", 9) == 0 ||
            strncmp(comm, "kworker", 7) == 0);
}

static bool pid_is_alive(pid_t pid)
{
    struct pid *p;
    struct task_struct *t;

    if (!pid)
        return false;

    p = find_get_pid(pid);
    if (!p)
        return false;

    t = pid_task(p, PIDTYPE_PID);
    put_pid(p);
    return t != NULL;
}

static enum conn_state tcp_derive_state(struct sk_buff *skb, bool incoming)
{
    struct tcphdr *tcp;

    if (!skb_transport_header_was_set(skb))
        return CONN_STATE_ESTABLISHED;
    if (!pskb_may_pull(skb, skb_transport_offset(skb) + sizeof(struct tcphdr)))
        return CONN_STATE_ESTABLISHED;

    tcp = (struct tcphdr *)skb_transport_header(skb);

    if (tcp->rst)
        return CONN_STATE_CLOSED;
    if (tcp->fin)
        return CONN_STATE_FIN_WAIT;
    if (tcp->syn && tcp->ack)
        return CONN_STATE_ESTABLISHED;
    if (tcp->syn && !tcp->ack)
        return incoming ? CONN_STATE_SYN_RECV : CONN_STATE_SYN_SENT;

    return CONN_STATE_ESTABLISHED;
}

static bool ipv6_find_transport(struct sk_buff *skb,
                                u8 *protocol,
                                int *transport_off)
{
    struct ipv6hdr *ip6;
    u8 nexthdr;
    int offset = sizeof(struct ipv6hdr);

    if (!pskb_may_pull(skb, sizeof(struct ipv6hdr)))
        return false;

    ip6 = (struct ipv6hdr *)skb->data;
    nexthdr = ip6->nexthdr;

    while (nexthdr == NEXTHDR_HOP ||
           nexthdr == NEXTHDR_ROUTING ||
           nexthdr == NEXTHDR_DEST ||
           nexthdr == NEXTHDR_FRAGMENT ||
           nexthdr == NEXTHDR_AUTH)
    {
        if (nexthdr == NEXTHDR_FRAGMENT)
        {
            struct frag_hdr *fh;

            if (!pskb_may_pull(skb, offset + sizeof(*fh)))
                return false;
            fh = (struct frag_hdr *)(skb->data + offset);
            if (ntohs(fh->frag_off) & ~0x7)
                return false;
            nexthdr = fh->nexthdr;
            offset += sizeof(*fh);
            continue;
        }

        if (nexthdr == NEXTHDR_AUTH)
        {
            struct ipv6_opt_hdr *ah;

            if (!pskb_may_pull(skb, offset + sizeof(*ah)))
                return false;
            ah = (struct ipv6_opt_hdr *)(skb->data + offset);
            nexthdr = ah->nexthdr;
            offset += (ah->hdrlen + 2) << 2;
            continue;
        }

        {
            struct ipv6_opt_hdr *opthdr;

            if (!pskb_may_pull(skb, offset + sizeof(*opthdr)))
                return false;
            opthdr = (struct ipv6_opt_hdr *)(skb->data + offset);
            nexthdr = opthdr->nexthdr;
            offset += (opthdr->hdrlen + 1) << 3;
        }
    }

    if (nexthdr != IPPROTO_TCP && nexthdr != IPPROTO_UDP)
        return false;

    *protocol = nexthdr;
    *transport_off = offset;
    return true;
}

/* ================================================================
 * parse_packet
 * ================================================================ */
void parse_packet(struct sk_buff *skb, bool incoming)
{
    struct iphdr *ip = NULL;
    struct ipv6hdr *ip6 = NULL;
    __be32 saddr = 0, daddr = 0;
    __u16 src_port = 0, dest_port = 0;
    __u8 protocol = 0;
    bool is_ipv6 = false;

    pid_t pid = 0;
    uid_t uid = 0;
    char comm[TASK_COMM_LEN] = {0};
    char exe[EXE_PATH_MAX] = {0};

    pid_t real_pid = 0;
    bool is_resolved = false;
    bool should_scan = false;
    bool is_new_conn = false;
    bool tcp_syn_only = false;

    enum conn_state state = CONN_STATE_ESTABLISHED;

    struct pid *pid_struct = NULL;
    struct task_struct *task = NULL;
    struct sock *sk = NULL;

    /* ================================================================
     * 1. IP VERSION DETECTION
     *
     * At NF_INET_LOCAL_OUT / NF_INET_LOCAL_IN hooks skb->protocol is
     * unreliable (often 0 for locally generated packets).  Read the
     * version nibble from skb->data directly — it is valid at both
     * hook points and works for IPv4 and IPv6.
     * ================================================================ */
    if (!skb)
        return;
    if (!pskb_may_pull(skb, 1))
        return;

    switch (((struct iphdr *)skb->data)->version)
    {

    case 4:
        if (!pskb_may_pull(skb, sizeof(struct iphdr)))
            return;
        ip = (struct iphdr *)skb->data;
        if (!ip)
            return;
        protocol = ip->protocol;
        if (protocol != IPPROTO_TCP && protocol != IPPROTO_UDP)
            return;
        saddr = ip->saddr;
        daddr = ip->daddr;
        skb_set_transport_header(skb, ip->ihl * 4);
        break;

    case 6:
    {
        int transport_off;

        if (!ipv6_find_transport(skb, &protocol, &transport_off))
            return;
        ip6 = (struct ipv6hdr *)skb->data;
        if (!ip6)
            return;
        /*
         * Store last 32 bits of each IPv6 address.  For connections
         * to real IPv4 hosts via v4-mapped addresses this gives the
         * correct IPv4 address.  Full 128-bit support can be added
         * later when the flow_key and traffic_entry structs are
         * extended.
         */
        saddr = ip6->saddr.s6_addr32[3];
        daddr = ip6->daddr.s6_addr32[3];
        is_ipv6 = true;
        skb_set_transport_header(skb, transport_off);
        break;
    }

    default:
        return;
    }

    /* ================================================================
     * 2. PORTS + STATE
     *
     * skb_transport_header() is valid for both IPv4 and IPv6 here
     * because we called skb_set_transport_header() above.
     * Do NOT use ip_hdrlen() in the IPv6 path — it reads the IPv4
     * IHL field from garbage memory and gives a wrong offset.
     * ================================================================ */
    if (protocol == IPPROTO_TCP)
    {
        struct tcphdr *tcp;

        if (!pskb_may_pull(skb,
                           skb_transport_offset(skb) + sizeof(struct tcphdr)))
            return;

        tcp = (struct tcphdr *)skb_transport_header(skb);
        src_port = ntohs(tcp->source);
        dest_port = ntohs(tcp->dest);
        state = tcp_derive_state(skb, incoming);

        if (tcp->syn && !tcp->ack)
            tcp_syn_only = true;
    }
    else
    { /* IPPROTO_UDP */
        struct udphdr *udp;

        if (!pskb_may_pull(skb,
                           skb_transport_offset(skb) + sizeof(struct udphdr)))
            return;

        udp = (struct udphdr *)skb_transport_header(skb);
        src_port = ntohs(udp->source);
        dest_port = ntohs(udp->dest);
        state = CONN_STATE_UDP_ACTIVE;
    }

    if (src_port == 0 || dest_port == 0)
        return;

    /* ================================================================
     * 3. FLOW KEY
     * ================================================================ */
    {
        struct flow_key key;

        memset(&key, 0, sizeof(key));
        key.src_ip = saddr;
        key.dest_ip = daddr;
        key.src_port = htons(src_port);
        key.dest_port = htons(dest_port);
        key.protocol = protocol;

        if (tcp_syn_only && !flow_cache_exists(&key))
            is_new_conn = true;

        /* ================================================================
         * 4. SOCKET
         * ================================================================ */
        sk = skb_to_full_sk(skb);

        /* ================================================================
         * 5. NO SOCKET PATH
         * ================================================================ */
        if (!sk)
        {
            real_pid = flow_cache_lookup(&key, &should_scan);
            if (real_pid > 0 && pid_is_alive(real_pid))
            {
                is_resolved = true;
                pid = real_pid;
                goto update_stats;
            }
            flow_cache_mark_negative(&key);
            return;
        }

        /* ================================================================
         * 6. UID
         * ================================================================ */
        uid = sock_i_uid(sk).val;

        /* ================================================================
         * 7. PID RESOLUTION
         * ================================================================ */

        /* 7a. Sock cache */
        real_pid = sock_cache_lookup(sk);
        if (real_pid)
        {
            if (pid_is_alive(real_pid))
            {
                is_resolved = true;
                flow_cache_mark_resolved(&key, real_pid);
                goto done;
            }
            exe_cache_invalidate(real_pid);
            real_pid = 0;
        }

        /* 7b. Inode cache — use sock_i_ino() for safe atomic access
         *     instead of chasing sk->sk_socket->file which can be
         *     freed concurrently (use-after-free). */
        {
            unsigned long ino = sock_i_ino(sk);
            if (ino)
            {
                real_pid = inode_cache_lookup(ino);
                if (real_pid && pid_is_alive(real_pid))
                {
                    is_resolved = true;
                    sock_cache_insert(sk, real_pid);
                    flow_cache_mark_resolved(&key, real_pid);
                    goto done;
                }
                else if (real_pid)
                {
                    inode_cache_invalidate(ino);
                    exe_cache_invalidate(real_pid);
                    real_pid = 0;
                }
            }
        }

        /* 7c. Flow cache */
        real_pid = flow_cache_lookup(&key, &should_scan);
        if (real_pid > 0 && pid_is_alive(real_pid))
        {
            is_resolved = true;
            goto done;
        }

        /* 7d. Full resolver — use sock_i_ino() to avoid UAF on sk_socket */
        if (should_scan)
        {
            unsigned long ino = sock_i_ino(sk);

            real_pid = resolve_pid_from_inode(ino);
            if (!real_pid && sk->sk_socket && sk->sk_socket->file)
                real_pid = resolve_pid_from_file(sk->sk_socket->file);

            if (real_pid > 0 && pid_is_alive(real_pid))
            {
                is_resolved = true;
                sock_cache_insert(sk, real_pid);
                flow_cache_mark_resolved(&key, real_pid);
            }
            else
            {
                resolver_schedule(ino, sk,
                                  (sk->sk_socket ? sk->sk_socket->file : NULL));
                flow_cache_mark_negative(&key);
                return;
            }
            goto done;
        }

        return;

    done:
        pid = real_pid;
    } /* end flow_key scope */

    /* ================================================================
     * 8. TASK LOOKUP
     * ================================================================ */
update_stats:
    rcu_read_lock();
    pid_struct = find_get_pid(pid);
    if (pid_struct)
        task = pid_task(pid_struct, PIDTYPE_PID);

    if (task)
        get_task_comm(comm, task);
    else
        strncpy(comm, "unknown", TASK_COMM_LEN);

    rcu_read_unlock();
    put_pid(pid_struct);
    pid_struct = NULL;

    if (pid == 0 || is_kernel_thread(comm))
        return;

    /* ================================================================
     * 9. EXE PATH LOOKUP (async — softirq safe)
     * ================================================================ */
    if (!exe_cache_lookup(pid, exe, sizeof(exe)))
    {
        resolver_schedule_exe(pid);
        exe[0] = '\0';
    }

    /* ================================================================
     * 10. RECORD
     * ================================================================ */
    stats_update(
        pid, uid, comm, exe,
        protocol,
        saddr, daddr,
        src_port, dest_port,
        skb->len,
        incoming,
        is_resolved,
        state,
        is_new_conn);
}
