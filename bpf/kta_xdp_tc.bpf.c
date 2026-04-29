#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/pkt_cls.h>

#define KTA_SAMPLE_LEN 128
#define KTA_MAX_EXT_HEADERS 6

typedef struct flow_key_t {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8 proto;
    __u8 pad[3];
} flow_key_t;

typedef struct flow_stats_t {
    __u64 packets;
    __u64 bytes;
    __u64 first_seen;
    __u64 last_seen;
    __u8 tcp_flags;
    __u8 dpi_hint;
    __u8 payload_sample[KTA_SAMPLE_LEN];
} flow_stats_t;

typedef struct event_t {
    flow_key_t key;
    __u32 pkt_len;
    __u8 tcp_flags;
    __u8 payload[KTA_SAMPLE_LEN];
} event_t;

typedef struct packet_info_t {
    flow_key_t key;
    __u32 pkt_len;
    __u32 payload_off;
    __u32 payload_len;
    __u8 tcp_flags;
    __u8 dpi_hint;
} packet_info_t;

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1000000);
    __type(key, flow_key_t);
    __type(value, flow_stats_t);
} kta_flows SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 256);
    __type(key, __u32);
    __type(value, __u64);
} kta_proto_bytes SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 16 * 1024 * 1024);
} kta_events SEC(".maps");

static __always_inline int is_ext(__u8 nh)
{
    return nh == 0 || nh == 43 || nh == 44 || nh == 51 || nh == 60;
}

static __always_inline void canonicalize(flow_key_t *key)
{
    if (key->src_ip > key->dst_ip) {
        __u32 ip = key->src_ip;
        __u16 port = key->src_port;
        key->src_ip = key->dst_ip;
        key->dst_ip = ip;
        key->src_port = key->dst_port;
        key->dst_port = port;
    }
}

static __always_inline __u8 dpi_hint(void *payload, void *data_end, __u16 sport, __u16 dport)
{
    __u8 *p = payload;

    if (p + 12 <= (__u8 *)data_end && (sport == 53 || dport == 53))
        return 1;
    if (p + 4 <= (__u8 *)data_end) {
        if (p[0] == 'G' && p[1] == 'E' && p[2] == 'T' && p[3] == ' ')
            return 2;
        if (p[0] == 'P' && p[1] == 'O' && p[2] == 'S' && p[3] == 'T')
            return 2;
        if (p[0] == 'P' && p[1] == 'U' && p[2] == 'T' && p[3] == ' ')
            return 2;
        if (p[0] == 'H' && p[1] == 'E' && p[2] == 'A' && p[3] == 'D')
            return 2;
        if (p[0] == 'H' && p[1] == 'T' && p[2] == 'T' && p[3] == 'P')
            return 2;
    }
    if (p + 5 <= (__u8 *)data_end && p[0] == 0x16 && p[1] == 0x03)
        return 3;
    return 0;
}

static __always_inline int parse_packet(void *data, void *data_end, packet_info_t *info)
{
    __u8 *cursor = data;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return 0;

    __u16 eth_proto = bpf_ntohs(eth->h_proto);
    cursor += sizeof(*eth);
    if (eth_proto == ETH_P_8021Q || eth_proto == ETH_P_8021AD) {
        if (cursor + 4 > (__u8 *)data_end)
            return 0;
        eth_proto = bpf_ntohs(*(__u16 *)(cursor + 2));
        cursor += 4;
    }

    __u8 proto = 0;
    if (eth_proto == ETH_P_IP) {
        struct iphdr *ip = (struct iphdr *)cursor;
        if ((void *)(ip + 1) > data_end)
            return 0;
        __u32 ihl = ip->ihl * 4;
        if (ihl < sizeof(*ip) || cursor + ihl > (__u8 *)data_end)
            return 0;
        info->key.src_ip = ip->saddr;
        info->key.dst_ip = ip->daddr;
        proto = ip->protocol;
        cursor += ihl;
    } else if (eth_proto == ETH_P_IPV6) {
        struct ipv6hdr *ip6 = (struct ipv6hdr *)cursor;
        if ((void *)(ip6 + 1) > data_end)
            return 0;
        __builtin_memcpy(&info->key.src_ip, &ip6->saddr.s6_addr[12], sizeof(info->key.src_ip));
        __builtin_memcpy(&info->key.dst_ip, &ip6->daddr.s6_addr[12], sizeof(info->key.dst_ip));
        proto = ip6->nexthdr;
        cursor += sizeof(*ip6);

#pragma unroll
        for (int i = 0; i < KTA_MAX_EXT_HEADERS; i++) {
            if (!is_ext(proto))
                break;
            if (cursor + 2 > (__u8 *)data_end)
                return 0;
            __u8 next = cursor[0];
            __u32 ext_len = proto == 51 ? ((__u32)cursor[1] + 2) * 4 : ((__u32)cursor[1] + 1) * 8;
            if (proto == 44)
                ext_len = 8;
            if (cursor + ext_len > (__u8 *)data_end)
                return 0;
            proto = next;
            cursor += ext_len;
        }
    } else {
        return 0;
    }

    info->key.proto = proto;
    if (proto == IPPROTO_TCP) {
        struct tcphdr *tcp = (struct tcphdr *)cursor;
        if ((void *)(tcp + 1) > data_end)
            return 0;
        __u32 thl = tcp->doff * 4;
        if (thl < sizeof(*tcp) || cursor + thl > (__u8 *)data_end)
            return 0;
        info->key.src_port = bpf_ntohs(tcp->source);
        info->key.dst_port = bpf_ntohs(tcp->dest);
        info->tcp_flags = ((__u8 *)tcp)[13];
        info->payload_off = cursor + thl - (__u8 *)data;
        info->payload_len = (__u8 *)data_end - (cursor + thl);
        info->dpi_hint = dpi_hint(cursor + thl, data_end, info->key.src_port, info->key.dst_port);
    } else if (proto == IPPROTO_UDP) {
        struct udphdr *udp = (struct udphdr *)cursor;
        if ((void *)(udp + 1) > data_end)
            return 0;
        info->key.src_port = bpf_ntohs(udp->source);
        info->key.dst_port = bpf_ntohs(udp->dest);
        info->tcp_flags = 0;
        info->payload_off = cursor + sizeof(*udp) - (__u8 *)data;
        info->payload_len = (__u8 *)data_end - (cursor + sizeof(*udp));
        info->dpi_hint = dpi_hint(cursor + sizeof(*udp), data_end, info->key.src_port, info->key.dst_port);
    } else {
        return 0;
    }

    canonicalize(&info->key);
    return 1;
}

static __always_inline void copy_sample_xdp(__u8 *dst, void *payload, void *data_end)
{
    __u8 *src = payload;

#pragma unroll
    for (int i = 0; i < KTA_SAMPLE_LEN; i++) {
        if (src + i + 1 <= (__u8 *)data_end)
            dst[i] = src[i];
        else
            dst[i] = 0;
    }
}

static __always_inline void update_maps(packet_info_t *info, void *payload, void *data_end, int submit_event)
{
    __u64 now = bpf_ktime_get_ns();
    flow_stats_t init = {};
    init.first_seen = now;
    init.last_seen = now;
    init.dpi_hint = info->dpi_hint;

    flow_stats_t *stats = bpf_map_lookup_elem(&kta_flows, &info->key);
    if (!stats) {
        bpf_map_update_elem(&kta_flows, &info->key, &init, BPF_NOEXIST);
        stats = bpf_map_lookup_elem(&kta_flows, &info->key);
        submit_event = 1;
    }
    if (stats) {
        __sync_fetch_and_add(&stats->packets, 1);
        __sync_fetch_and_add(&stats->bytes, info->pkt_len);
        stats->last_seen = now;
        stats->tcp_flags |= info->tcp_flags;
        if (stats->dpi_hint == 0)
            stats->dpi_hint = info->dpi_hint;
        copy_sample_xdp(stats->payload_sample, payload, data_end);
    }

    __u32 proto_key = info->key.proto;
    __u64 *proto_bytes = bpf_map_lookup_elem(&kta_proto_bytes, &proto_key);
    if (proto_bytes)
        __sync_fetch_and_add(proto_bytes, info->pkt_len);

    if (submit_event) {
        event_t *event = bpf_ringbuf_reserve(&kta_events, sizeof(*event), 0);
        if (event) {
            event->key = info->key;
            event->pkt_len = info->pkt_len;
            event->tcp_flags = info->tcp_flags;
            copy_sample_xdp(event->payload, payload, data_end);
            bpf_ringbuf_submit(event, 0);
        }
    }
}

SEC("xdp")
int kta_xdp(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    packet_info_t info = {};
    info.pkt_len = (__u32)((__u8 *)data_end - (__u8 *)data);

    if (parse_packet(data, data_end, &info)) {
        void *payload = (__u8 *)data + info.payload_off;
        int submit_event = info.tcp_flags & 0x02;
        update_maps(&info, payload, data_end, submit_event);
    }

    return XDP_PASS;
}

SEC("tc")
int kta_tc_egress(struct __sk_buff *skb)
{
    __u8 data[256] = {};
    __u32 copy_len = skb->len < sizeof(data) ? skb->len : sizeof(data);
    if (bpf_skb_load_bytes(skb, 0, data, copy_len) < 0)
        return TC_ACT_OK;

    void *data_end = data + copy_len;
    packet_info_t info = {};
    info.pkt_len = skb->len;

    if (parse_packet(data, data_end, &info)) {
        void *payload = data + info.payload_off;
        int submit_event = info.tcp_flags & 0x02;
        update_maps(&info, payload, data_end, submit_event);
    }

    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
