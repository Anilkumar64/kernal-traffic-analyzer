// SPDX-License-Identifier: GPL-2.0
/*
 * Kernel Traffic Analyzer eBPF fast-path programs.
 *
 * This file is the kernel-side companion to backend/kta_packet_backend. It is
 * intentionally small: XDP/TC do early parsing, maintain flow counters, and emit
 * compact metadata. Deep dissection, DPI, and stream reconstruction stay in C++.
 *
 * Build example:
 *   clang -O2 -g -target bpf -D__TARGET_ARCH_x86 \
 *     -c bpf/kta_xdp_tc.bpf.c -o build/kta_xdp_tc.bpf.o
 */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/if_vlan.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

struct flow_key {
    __u8 family;
    __u8 proto;
    __u16 sport;
    __u16 dport;
    __u32 src4;
    __u32 dst4;
    __u8 src6[16];
    __u8 dst6[16];
};

struct flow_stats {
    __u64 packets;
    __u64 bytes;
    __u64 first_ns;
    __u64 last_ns;
    __u8 tcp_flags;
};

struct packet_event {
    __u64 ts_ns;
    struct flow_key key;
    __u32 packet_len;
    __u16 payload_off;
    __u16 payload_len;
    __u32 seq;
    __u32 ack;
    __u8 tcp_flags;
    __u8 dpi_hint;
    __u8 sample[128];
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1048576);
    __type(key, struct flow_key);
    __type(value, struct flow_stats);
} kta_flows SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 256);
    __type(key, __u32);
    __type(value, __u64);
} kta_proto_bytes SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} kta_events SEC(".maps");

static __always_inline int parse_eth(void *data, void *data_end, __u64 *off,
                                     __u16 *eth_proto)
{
    struct ethhdr *eth = data;

    if ((void *)(eth + 1) > data_end)
        return -1;

    *off = sizeof(*eth);
    *eth_proto = bpf_ntohs(eth->h_proto);

#pragma unroll
    for (int i = 0; i < 2; i++) {
        struct vlan_hdr *vh;

        if (*eth_proto != ETH_P_8021Q && *eth_proto != ETH_P_8021AD)
            break;
        vh = data + *off;
        if ((void *)(vh + 1) > data_end)
            return -1;
        *eth_proto = bpf_ntohs(vh->h_vlan_encapsulated_proto);
        *off += sizeof(*vh);
    }

    return 0;
}

static __always_inline __u8 scan_payload(void *payload, void *data_end,
                                         __u8 proto, __u16 sport, __u16 dport)
{
    __u8 *p = payload;

    if (proto == IPPROTO_UDP && (sport == 53 || dport == 53))
        return 3;
    if ((void *)(p + 8) > data_end)
        return 0;
    if (p[0] == 'G' && p[1] == 'E' && p[2] == 'T' && p[3] == ' ')
        return 1;
    if (p[0] == 'P' && p[1] == 'O' && p[2] == 'S' && p[3] == 'T')
        return 1;
    if (p[0] == 0x16 && p[5] == 0x01)
        return 2;
    return 0;
}

static __always_inline void count_flow(struct flow_key *key, __u64 bytes,
                                       __u8 tcp_flags)
{
    struct flow_stats init = {};
    struct flow_stats *stats;
    __u64 now = bpf_ktime_get_ns();

    init.first_ns = now;
    init.last_ns = now;
    bpf_map_update_elem(&kta_flows, key, &init, BPF_NOEXIST);
    stats = bpf_map_lookup_elem(&kta_flows, key);
    if (!stats)
        return;

    __sync_fetch_and_add(&stats->packets, 1);
    __sync_fetch_and_add(&stats->bytes, bytes);
    stats->last_ns = now;
    stats->tcp_flags |= tcp_flags;
}

static __always_inline int parse_l3_l4(void *data, void *data_end,
                                       struct flow_key *key, __u64 *l4off,
                                       __u16 *payload_off, __u16 *payload_len,
                                       __u32 *seq, __u32 *ack, __u8 *tcp_flags)
{
    __u64 off = 0;
    __u16 eth_proto = 0;

    if (parse_eth(data, data_end, &off, &eth_proto) < 0)
        return -1;

    if (eth_proto == ETH_P_IP) {
        struct iphdr *ip = data + off;
        __u32 ihl;

        if ((void *)(ip + 1) > data_end)
            return -1;
        ihl = ip->ihl * 4;
        if (ihl < sizeof(*ip) || data + off + ihl > data_end)
            return -1;
        if (ip->protocol != IPPROTO_TCP && ip->protocol != IPPROTO_UDP)
            return -1;

        key->family = AF_INET;
        key->proto = ip->protocol;
        key->src4 = ip->saddr;
        key->dst4 = ip->daddr;
        *l4off = off + ihl;
    } else if (eth_proto == ETH_P_IPV6) {
        struct ipv6hdr *ip6 = data + off;

        if ((void *)(ip6 + 1) > data_end)
            return -1;
        if (ip6->nexthdr != IPPROTO_TCP && ip6->nexthdr != IPPROTO_UDP)
            return -1;

        key->family = AF_INET6;
        key->proto = ip6->nexthdr;
        __builtin_memcpy(key->src6, &ip6->saddr, sizeof(key->src6));
        __builtin_memcpy(key->dst6, &ip6->daddr, sizeof(key->dst6));
        *l4off = off + sizeof(*ip6);
    } else {
        return -1;
    }

    if (key->proto == IPPROTO_TCP) {
        struct tcphdr *tcp = data + *l4off;
        __u32 thl;

        if ((void *)(tcp + 1) > data_end)
            return -1;
        thl = tcp->doff * 4;
        if (thl < sizeof(*tcp) || data + *l4off + thl > data_end)
            return -1;
        key->sport = bpf_ntohs(tcp->source);
        key->dport = bpf_ntohs(tcp->dest);
        *seq = bpf_ntohl(tcp->seq);
        *ack = bpf_ntohl(tcp->ack_seq);
        *tcp_flags = ((__u8 *)tcp)[13];
        *payload_off = *l4off + thl;
    } else {
        struct udphdr *udp = data + *l4off;

        if ((void *)(udp + 1) > data_end)
            return -1;
        key->sport = bpf_ntohs(udp->source);
        key->dport = bpf_ntohs(udp->dest);
        *payload_off = *l4off + sizeof(*udp);
    }

    if (data + *payload_off > data_end)
        return -1;
    *payload_len = data_end - (data + *payload_off);
    return 0;
}

SEC("xdp")
int kta_xdp_capture(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct flow_key key = {};
    struct packet_event *ev;
    __u64 l4off = 0;
    __u16 payload_off = 0;
    __u16 payload_len = 0;
    __u32 seq = 0;
    __u32 ack = 0;
    __u8 tcp_flags = 0;
    __u64 len = data_end - data;
    __u32 proto_idx;
    __u64 *proto_bytes;

    if (parse_l3_l4(data, data_end, &key, &l4off, &payload_off,
                    &payload_len, &seq, &ack, &tcp_flags) < 0)
        return XDP_PASS;

    count_flow(&key, len, tcp_flags);
    proto_idx = key.proto;
    proto_bytes = bpf_map_lookup_elem(&kta_proto_bytes, &proto_idx);
    if (proto_bytes)
        *proto_bytes += len;

    if ((bpf_get_prandom_u32() & 0x3f) != 0)
        return XDP_PASS;

    ev = bpf_ringbuf_reserve(&kta_events, sizeof(*ev), 0);
    if (!ev)
        return XDP_PASS;

    ev->ts_ns = bpf_ktime_get_ns();
    ev->key = key;
    ev->packet_len = len;
    ev->payload_off = payload_off;
    ev->payload_len = payload_len;
    ev->seq = seq;
    ev->ack = ack;
    ev->tcp_flags = tcp_flags;
    ev->dpi_hint = scan_payload(data + payload_off, data_end, key.proto,
                                key.sport, key.dport);

    __builtin_memset(ev->sample, 0, sizeof(ev->sample));
    bpf_xdp_load_bytes(ctx, 0, ev->sample,
                       len < sizeof(ev->sample) ? len : sizeof(ev->sample));
    bpf_ringbuf_submit(ev, 0);
    return XDP_PASS;
}

SEC("classifier")
int kta_tc_observe(struct __sk_buff *skb)
{
    /* TC attachment point placeholder: use this for egress, post-GRO, or
     * payload hints where skb helpers are more convenient than XDP.
     */
    return 0;
}

char LICENSE[] SEC("license") = "GPL";

