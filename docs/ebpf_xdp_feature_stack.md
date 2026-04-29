# eBPF/XDP Feature Stack for Kernel Traffic Analyzer

This document describes how to extend the current Kernel Traffic Analyzer from its
existing Netfilter + `/proc` design into a hybrid high-performance analyzer that
uses eBPF, XDP, TC, AF_PACKET, Netfilter, a C++17 middleware process, and the Qt
GUI already present in this repository.

The current codebase already has a useful process-aware Netfilter path:

```text
kernel_module/src/netfilter_hook.c
        |
kernel_module/src/packet_parser.c
        |
kernel_module/src/stats.c
        |
/proc/traffic_analyzer*
        |
gui/core/ProcReader.cpp
        |
Qt table/chart models
```

The proposed extension keeps that path for process attribution and compatibility,
then adds fast packet/flow paths:

```text
NIC RX
  |
  +-- XDP eBPF: early parse, flow counters, sample/metadata ringbuf
  |       |
  |       +-- BPF maps: flow table, per-CPU counters, stream hints
  |       +-- BPF ringbuf/perfbuf: events and selected packet samples
  |
  +-- Linux stack
          |
          +-- TC eBPF: payload prefilter, stream annotation
          +-- Netfilter module: process attribution, conn state, DNS map
          +-- AF_PACKET PACKET_MMAP: raw packet fallback and deep sampling
                  |
                  v
          C++17 daemon: libbpf, AF_PACKET, dissection, DPI, reassembly,
                        shared memory/ring IPC, NetFlow/IPFIX export
                  |
                  v
          Qt GUI: models, charts, follow-stream views
```

## 1. Kernel-Level High-Performance Capture

### What It Does

High-performance capture moves the first packet touch as close to the NIC as
possible. XDP runs before socket allocation, qdisc, Netfilter, and most of the
network stack. It is essential because the current Netfilter module sees packets
after SKB allocation, which is excellent for process attribution but expensive for
line-rate packet counting or selective packet sampling.

Use two capture paths:

- XDP for RX-side line-rate metadata extraction, counters, drops, redirects, and
  sampling.
- AF_PACKET with `PACKET_MMAP` for non-XDP interfaces, loopback traffic, TX
  visibility, and raw packet samples needed by the C++ dissector.

### Kernel/User Interaction

Recommended interfaces:

- `BPF_MAP_TYPE_LRU_HASH`: 5-tuple to flow entry.
- `BPF_MAP_TYPE_PERCPU_ARRAY`: per-CPU protocol/byte counters.
- `BPF_MAP_TYPE_RINGBUF`: metadata and small packet samples to user space.
- AF_PACKET `TPACKET_V3`: mmap'd RX rings for raw packets without per-packet
  `recvmsg()` copies.

XDP cannot directly share the full packet buffer with user space. The practical
"zero-copy" design is:

- For metadata: use BPF maps/ring buffers. The packet remains in kernel/NIC path.
- For raw packet fallback: use AF_PACKET `PACKET_MMAP`, where the kernel writes
  packet frames into an mmap'd ring consumed by C++.
- For true NIC zero-copy into user memory: add AF_XDP later. AF_PACKET is simpler
  and fits the current stack.

### XDP BPF Sketch

```c
/* bpf/xdp_kta.bpf.c */
struct flow_key {
    __u8  family;
    __u8  proto;
    __u16 sport;
    __u16 dport;
    __u32 src4;
    __u32 dst4;
};

struct flow_val {
    __u64 packets;
    __u64 bytes;
    __u64 first_ns;
    __u64 last_ns;
    __u8  tcp_flags;
};

struct packet_event {
    __u64 ts_ns;
    struct flow_key key;
    __u32 pkt_len;
    __u16 cap_len;
    __u8  direction;
    __u8  l4_flags;
    __u8  data[128];
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1048576);
    __type(key, struct flow_key);
    __type(value, struct flow_val);
} xdp_flows SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 256);
    __type(key, __u32);
    __type(value, __u64);
} proto_bytes SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} packet_events SEC(".maps");

static __always_inline int parse_ipv4(void *data, void *data_end,
                                      struct flow_key *key, __u64 *l4off)
{
    struct ethhdr *eth = data;
    struct iphdr *ip;

    if ((void *)(eth + 1) > data_end)
        return -1;
    if (eth->h_proto != __constant_htons(ETH_P_IP))
        return -1;

    ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return -1;
    if (ip->protocol != IPPROTO_TCP && ip->protocol != IPPROTO_UDP)
        return -1;

    key->family = AF_INET;
    key->proto = ip->protocol;
    key->src4 = ip->saddr;
    key->dst4 = ip->daddr;
    *l4off = sizeof(*eth) + ip->ihl * 4;
    return 0;
}

SEC("xdp")
int kta_xdp_capture(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct flow_key key = {};
    struct flow_val init = {};
    struct flow_val *val;
    __u64 l4off = 0;
    __u64 now = bpf_ktime_get_ns();
    __u64 len = data_end - data;

    if (parse_ipv4(data, data_end, &key, &l4off) < 0)
        return XDP_PASS;

    if (key.proto == IPPROTO_TCP) {
        struct tcphdr *tcp = data + l4off;
        if ((void *)(tcp + 1) > data_end)
            return XDP_PASS;
        key.sport = tcp->source;
        key.dport = tcp->dest;
    } else {
        struct udphdr *udp = data + l4off;
        if ((void *)(udp + 1) > data_end)
            return XDP_PASS;
        key.sport = udp->source;
        key.dport = udp->dest;
    }

    init.first_ns = now;
    init.last_ns = now;
    val = bpf_map_lookup_elem(&xdp_flows, &key);
    if (!val) {
        bpf_map_update_elem(&xdp_flows, &key, &init, BPF_NOEXIST);
        val = bpf_map_lookup_elem(&xdp_flows, &key);
    }
    if (val) {
        __sync_fetch_and_add(&val->packets, 1);
        __sync_fetch_and_add(&val->bytes, len);
        val->last_ns = now;
    }

    if ((bpf_get_prandom_u32() & 0xff) == 0) {
        struct packet_event *ev;
        __u32 cap = len < sizeof(ev->data) ? len : sizeof(ev->data);

        ev = bpf_ringbuf_reserve(&packet_events, sizeof(*ev), 0);
        if (ev) {
            ev->ts_ns = now;
            ev->key = key;
            ev->pkt_len = len;
            ev->cap_len = cap;
            bpf_xdp_load_bytes(ctx, 0, ev->data, cap);
            bpf_ringbuf_submit(ev, 0);
        }
    }

    return XDP_PASS;
}
```

### AF_PACKET `PACKET_MMAP` Fallback

```cpp
int fd = ::socket(AF_PACKET, SOCK_RAW | SOCK_NONBLOCK, htons(ETH_P_ALL));

int ver = TPACKET_V3;
setsockopt(fd, SOL_PACKET, PACKET_VERSION, &ver, sizeof(ver));

tpacket_req3 req{};
req.tp_block_size = 1 << 22;
req.tp_frame_size = 2048;
req.tp_block_nr = 64;
req.tp_frame_nr = (req.tp_block_size * req.tp_block_nr) / req.tp_frame_size;
req.tp_retire_blk_tov = 64;
setsockopt(fd, SOL_PACKET, PACKET_RX_RING, &req, sizeof(req));

void *ring = mmap(nullptr, req.tp_block_size * req.tp_block_nr,
                  PROT_READ | PROT_WRITE, MAP_SHARED | MAP_LOCKED, fd, 0);
```

### C++ Consumer to Qt

```cpp
struct PacketEvent {
    quint64 tsNs;
    FlowKey key;
    quint32 packetLength;
    QByteArray sample;
};

class BpfCapture : public QObject {
    Q_OBJECT
public:
    void start();
signals:
    void packetsReady(QVector<PacketEvent> batch);
private:
    static int onRingEvent(void *ctx, void *data, size_t len) {
        auto *self = static_cast<BpfCapture *>(ctx);
        self->batch_.push_back(copyEvent(data, len));
        if (self->batch_.size() >= 512)
            emit self->packetsReady(std::exchange(self->batch_, {}));
        return 0;
    }
    QVector<PacketEvent> batch_;
};

// Worker thread emits batches. GUI thread receives via queued connection.
connect(capture, &BpfCapture::packetsReady,
        trafficModel, &TrafficModel::applyPacketBatch,
        Qt::QueuedConnection);
```

### Throughput, Locking, and Multi-Core Scaling

Use per-CPU maps for hot counters and LRU hash maps for flow state. Avoid global
kernel locks on the fast path. Ring-buffer writes are used only for sampled
events, not every packet. In user space, use one reader thread per ring source
and batch Qt updates at 10-30 Hz; never update widgets per packet.

### Performance Gain

Compared with pure user-space capture, XDP avoids SKB allocation for early
decisions and reduces copies by exporting compact metadata. AF_PACKET
`PACKET_MMAP` removes per-packet syscall overhead. Expect much better packet rate
headroom, especially for small packets, while retaining the existing Netfilter
path for process-aware enrichment.

## 2. Full Protocol Dissection

### What It Does

Early BPF parsing extracts stable metadata: Ethernet/VLAN, IPv4/IPv6 addresses,
L4 protocol, ports, TCP flags, sequence numbers, and payload offset. User-space
C++ performs deep decoding: Ethernet, VLAN, IPv4/IPv6, TCP/UDP, DNS, HTTP, TLS,
and application-specific records.

This split is essential because BPF is bounded, verifier constrained, and should
avoid complex variable-length application parsing; C++ can handle rich protocol
state and memory-heavy parsing.

### Kernel/User Interaction

- XDP/TC program writes `packet_event` metadata to `BPF_MAP_TYPE_RINGBUF`.
- Flow table map stores counters and TCP hints.
- AF_PACKET provides full packet bytes for selected flows.
- C++ merges BPF metadata and raw samples by 5-tuple + timestamp.

### BPF Metadata Event

```c
struct parse_meta {
    __u64 ts_ns;
    struct flow_key key;
    __u32 seq;
    __u32 ack;
    __u16 payload_off;
    __u16 payload_len;
    __u8  tcp_flags;
    __u8  vlan_depth;
};

static __always_inline int fill_tcp_meta(void *data, void *data_end,
                                         __u64 l4off, struct parse_meta *m)
{
    struct tcphdr *tcp = data + l4off;
    __u16 hdr_len;

    if ((void *)(tcp + 1) > data_end)
        return -1;

    hdr_len = tcp->doff * 4;
    if (hdr_len < sizeof(*tcp))
        return -1;
    if (data + l4off + hdr_len > data_end)
        return -1;

    m->seq = tcp->seq;
    m->ack = tcp->ack_seq;
    m->tcp_flags = ((__u8 *)tcp)[13];
    m->payload_off = l4off + hdr_len;
    m->payload_len = data_end - (data + m->payload_off);
    return 0;
}
```

### C++ Dissector Sketch

```cpp
class ProtocolDissector {
public:
    DecodedPacket decode(const PacketView &pkt, const ParseMeta *meta) {
        DecodedPacket out;
        Ethernet eth = parseEthernet(pkt);
        while (eth.type == EtherType::Vlan)
            eth = parseVlan(pkt, eth.nextOffset);

        if (eth.type == EtherType::Ipv4)
            out.ip = parseIpv4(pkt, eth.nextOffset);
        else if (eth.type == EtherType::Ipv6)
            out.ip = parseIpv6(pkt, eth.nextOffset);

        if (out.ip.protocol == IPPROTO_TCP)
            out.tcp = parseTcp(pkt, out.ip.payloadOffset);
        else if (out.ip.protocol == IPPROTO_UDP)
            out.udp = parseUdp(pkt, out.ip.payloadOffset);

        if (meta && meta->payload_len > 0)
            out.app = decodeApplication(pkt.slice(meta->payload_off,
                                                  meta->payload_len),
                                        out.tcp, out.udp);
        return out;
    }
};
```

### Stateful Reassembly Hints

BPF should not reassemble streams. It should annotate:

- stream ID or hash.
- TCP sequence and ACK.
- SYN/FIN/RST flags.
- payload length.
- direction bit.

C++ stores these hints in a `StreamState` and uses them to detect gaps,
retransmits, and out-of-order data.

```cpp
void StreamState::observe(const ParseMeta &m, QByteArray payload) {
    auto &side = sideFor(m.key);
    if (m.seq == side.nextSeq) {
        appendInOrder(payload);
        side.nextSeq += payload.size();
        drainQueuedSegments(side);
    } else if (seqAfter(m.seq, side.nextSeq)) {
        side.outOfOrder.emplace(m.seq, std::move(payload));
    } else {
        side.retransmits++;
    }
}
```

### Throughput, Locking, and Multi-Core Scaling

BPF performs only fixed-bound parsing. User-space dissectors run in worker
threads partitioned by flow hash, which keeps a TCP flow on one worker and avoids
per-flow locks. Metadata batches move through single-producer/single-consumer
queues or shared memory rings.

### Performance Gain

Pure user-space dissection must parse every packet from raw bytes. The kernel
metadata path lets user space skip early parsing for most packets and reserve
full protocol decoding for sampled, interesting, or UI-visible flows.

## 3. Real-Time Flow and Connection Tracking

### What It Does

Flow tracking keeps a live 5-tuple cache with counters, timestamps, TCP state,
and process attribution hints. It is essential for top talkers, bandwidth
graphs, anomaly detection, and NetFlow/IPFIX export.

The current module already has a flow cache in `kernel_module/src/flow_cache.c`
for PID resolution. The eBPF extension adds a high-rate packet counter cache,
while Netfilter continues to enrich local flows with PID/UID/command/exe.

### Kernel/User Interaction

- XDP: `BPF_MAP_TYPE_LRU_HASH` from 5-tuple to byte/packet counters.
- Per-CPU maps: hot protocol and interface counters.
- Netfilter: process-aware stats in existing `traffic_entry`.
- Optional conntrack: use Netfilter hooks to correlate with `nf_conn` state for
  NATed or forwarded flows.
- C++ daemon periodically sweeps BPF maps and `/proc/traffic_analyzer*`.

### BPF Flow Update

```c
struct flow_stats {
    __u64 packets;
    __u64 bytes;
    __u64 first_ns;
    __u64 last_ns;
    __u8  state;
};

static __always_inline void update_flow(struct flow_key *key, __u64 bytes,
                                        __u8 tcp_flags)
{
    struct flow_stats zero = {};
    struct flow_stats *s;
    __u64 now = bpf_ktime_get_ns();

    zero.first_ns = now;
    zero.last_ns = now;
    bpf_map_update_elem(&xdp_flows, key, &zero, BPF_NOEXIST);
    s = bpf_map_lookup_elem(&xdp_flows, key);
    if (!s)
        return;

    __sync_fetch_and_add(&s->packets, 1);
    __sync_fetch_and_add(&s->bytes, bytes);
    s->last_ns = now;
    if (tcp_flags & TH_SYN)
        s->state = 1;
    if (tcp_flags & TH_FIN)
        s->state = 2;
    if (tcp_flags & TH_RST)
        s->state = 3;
}
```

### Netfilter Conntrack Integration

```c
#include <net/netfilter/nf_conntrack.h>

static unsigned int packet_in_hook(void *priv, struct sk_buff *skb,
                                   const struct nf_hook_state *state)
{
    enum ip_conntrack_info ctinfo;
    struct nf_conn *ct = nf_ct_get(skb, &ctinfo);

    if (ct) {
        /* ctinfo exposes original/reply direction and connection state.
         * Use this as enrichment; keep XDP counters as the high-rate source.
         */
    }

    parse_packet(skb, true);
    return NF_ACCEPT;
}
```

### C++ Sweeper and IPFIX Export

```cpp
class FlowSweeper : public QObject {
    Q_OBJECT
public:
    void sweep() {
        QVector<FlowRecord> out;
        FlowKey key{}, next{};

        while (bpf_map_get_next_key(flowFd_, keyValid_ ? &key : nullptr, &next) == 0) {
            FlowStats stats{};
            if (bpf_map_lookup_elem(flowFd_, &next, &stats) == 0)
                out.push_back(toRecord(next, stats));
            key = next;
            keyValid_ = true;
        }

        ipfix_.exportRecords(out);
        emit flowsUpdated(out);
    }
signals:
    void flowsUpdated(QVector<FlowRecord>);
private:
    int flowFd_ = -1;
    bool keyValid_ = false;
    IpfixExporter ipfix_;
};
```

### Qt Top Talkers

```cpp
connect(sweeper, &FlowSweeper::flowsUpdated,
        topTalkerModel, &TopTalkerModel::replaceSnapshot,
        Qt::QueuedConnection);
```

### Throughput, Locking, and Multi-Core Scaling

Use BPF LRU maps to cap memory automatically. For very hot counters, prefer
per-CPU values and aggregate in C++ at sweep time. In C++, partition maps by flow
hash for processing and use immutable snapshots for Qt models.

### Performance Gain

Compared with pure user-space flow tracking, BPF maps update counters before
packet copies or socket delivery. User space reads compact counters periodically
instead of ingesting every packet just to maintain top-talker state.

## 4. Live Graphical Dashboards

### What It Does

Dashboards show live throughput by protocol, process, IP, route, DNS domain,
interface, and anomaly class. The Qt GUI must stay responsive while the capture
pipeline runs at high packet rates.

The current GUI already uses Qt models fed by `ProcReader::readAll()`. The
extension adds a C++ middleware daemon that emits binary snapshots through shared
memory or an mmap'd ring. The GUI consumes aggregated snapshots, not packets.

### Kernel/User Interaction

- BPF maps: source of counters.
- C++ daemon: aggregation and downsampling.
- Shared memory ring: daemon-to-GUI IPC.
- Qt: reads snapshots on a worker object and updates models on the UI thread.

### Shared Memory Snapshot Protocol

```cpp
struct SnapshotHeader {
    quint32 magic = 0x4b544153; /* KTAS */
    quint16 version = 1;
    quint16 type;
    quint64 sequence;
    quint64 timestampNs;
    quint32 payloadBytes;
    quint32 recordCount;
};

struct MetricRecord {
    quint32 kind;      /* protocol, ip, process, dns, route */
    quint32 id;
    quint64 bytesIn;
    quint64 bytesOut;
    quint64 packetsIn;
    quint64 packetsOut;
};
```

### Middleware Aggregator

```cpp
class MetricsPublisher {
public:
    void publish(const QVector<FlowRecord> &flows,
                 const QVector<ProcEntry> &processes) {
        QVector<MetricRecord> records;
        records += aggregateByProtocol(flows);
        records += aggregateByRemoteIp(flows);
        records += aggregateByProcess(processes);

        SnapshotHeader h;
        h.sequence = ++seq_;
        h.timestampNs = monotonicNs();
        h.recordCount = records.size();
        h.payloadBytes = records.size() * sizeof(MetricRecord);

        ring_.write(h, records.constData(), h.payloadBytes);
    }
private:
    quint64 seq_ = 0;
    MmapRingWriter ring_;
};
```

### Qt Model Updates Without Blocking

```cpp
class MetricsReader : public QObject {
    Q_OBJECT
public slots:
    void poll() {
        QVector<MetricRecord> batch;
        while (ring_.tryRead(batch))
            latest_ = std::move(batch);
        if (!latest_.isEmpty())
            emit metricsReady(latest_);
    }
signals:
    void metricsReady(QVector<MetricRecord>);
private:
    QVector<MetricRecord> latest_;
    MmapRingReader ring_;
};

connect(reader, &MetricsReader::metricsReady,
        dashboardModel, &DashboardModel::replaceMetrics,
        Qt::QueuedConnection);
```

### Throughput, Locking, and Multi-Core Scaling

The daemon owns the write side of the ring and the GUI owns the read side.
Records are fixed size and sequence numbered. The UI consumes only the newest
snapshot when it falls behind. Batching to 10-30 frames per second keeps charts
smooth without burning CPU.

### Performance Gain

Pure user-space dashboards often over-couple packet ingestion and rendering.
Kernel aggregation plus binary snapshot IPC keeps the GUI proportional to the
number of displayed series, not the packet rate.

## 5. Deep Packet Inspection

### What It Does

DPI identifies application protocols and suspicious payloads. BPF performs cheap
prefiltering for patterns such as HTTP methods, TLS ClientHello, DNS opcodes, or
fixed byte signatures. C++ performs heavier classification using nDPI,
libprotoident, or project-local decoders only for flagged samples.

This is essential because full DPI on every packet in user space is expensive,
while full DPI in BPF is constrained by the verifier and instruction limits.

### Kernel/User Interaction

- XDP/TC eBPF scans bounded payload windows.
- Flagged packet metadata/sample goes to ring buffer.
- C++ receives the sample and decides whether to request more AF_PACKET samples
  for the flow.
- Qt displays protocol labels, confidence, and extracted indicators.

### BPF Lightweight Pattern Matching

```c
enum dpi_hint {
    DPI_NONE = 0,
    DPI_HTTP = 1,
    DPI_TLS_CLIENT_HELLO = 2,
};

static __always_inline __u8 scan_payload(void *payload, void *data_end)
{
    __u8 *b = payload;

    if ((void *)(b + 8) > data_end)
        return DPI_NONE;

    if (b[0] == 'G' && b[1] == 'E' && b[2] == 'T' && b[3] == ' ')
        return DPI_HTTP;
    if (b[0] == 'P' && b[1] == 'O' && b[2] == 'S' && b[3] == 'T')
        return DPI_HTTP;

    /* TLS record: handshake(22), version, length, ClientHello(1). */
    if ((__u8)b[0] == 0x16 && (__u8)b[5] == 0x01)
        return DPI_TLS_CLIENT_HELLO;

    return DPI_NONE;
}
```

At TC ingress/egress, SKB helpers can be used:

```c
SEC("classifier")
int kta_tc_dpi(struct __sk_buff *skb)
{
    __u8 window[64];
    __u32 payload_offset = 54; /* Example: Ethernet + IPv4 + TCP without options. */

    if (bpf_skb_load_bytes(skb, payload_offset, window, sizeof(window)) < 0)
        return TC_ACT_OK;

    /* Run bounded scans and emit only hints. */
    return TC_ACT_OK;
}
```

### C++ Heavy DPI

```cpp
class DpiEngine {
public:
    DpiResult inspect(const PacketEvent &ev) {
        if (ev.hint == DpiHint::Http)
            return inspectHttp(ev.sample);
        if (ev.hint == DpiHint::TlsClientHello)
            return inspectTlsClientHello(ev.sample); // SNI, ALPN, JA3/JA4

        // Optional: pass selected packets to nDPI/libprotoident.
        return ndpi_.classify(ev.key, ev.sample);
    }
};
```

### Verifier Limits

Keep BPF DPI simple:

- Scan fixed windows such as 64, 128, or 256 bytes.
- Use bounded loops with compile-time limits.
- Avoid dynamic pointer arithmetic without explicit `data_end` checks.
- Emit hints rather than large strings.
- Put complex JA3/JA4 canonicalization in C++.

### Throughput, Locking, and Multi-Core Scaling

BPF emits DPI events only for first packets, known ports, or sampled payloads.
The C++ DPI pool is flow-hash partitioned, so protocol state is single-threaded
per flow. Backpressure is handled by dropping low-priority samples, not blocking
XDP/TC.

### Performance Gain

Compared with pure user-space DPI, BPF prefiltering massively reduces the number
of packets that enter expensive classifiers. Compared with full in-kernel DPI,
this keeps the kernel path verifier-friendly and safe.

## 6. TCP Stream Reconstruction and Content Extraction

### What It Does

Stream reconstruction rebuilds byte streams from TCP segments and extracts
content such as HTTP responses, SMTP attachments, or SMB file transfers. Full
reassembly belongs in user space, but the kernel can annotate packets with flow
IDs, sequence numbers, ACKs, flags, and worker steering hints.

This is essential for "Follow TCP Stream", file extraction, and protocol-aware
forensics.

### Kernel/User Interaction

- BPF metadata includes stream ID, direction, sequence, ACK, payload offset, and
  payload length.
- C++ workers are selected by `hash(flow_key) % worker_count`.
- Optional `SO_ATTACH_REUSEPORT_CBPF`/eBPF steers packet sockets or UDP/TCP
  sockets by flow hash.
- Qt opens stream views from reconstructed user-space state.

### BPF Stream Annotation

```c
struct stream_hint {
    __u64 stream_id;
    struct flow_key key;
    __u32 seq;
    __u32 ack;
    __u16 payload_len;
    __u8  direction;
    __u8  flags;
};

static __always_inline __u64 flow_id(const struct flow_key *k)
{
    __u64 h = 1469598103934665603ULL;
    const __u8 *p = (const __u8 *)k;

#pragma unroll
    for (int i = 0; i < sizeof(*k); i++) {
        h ^= p[i];
        h *= 1099511628211ULL;
    }

    return h;
}
```

In XDP, compute a canonical hash manually with a bounded helper like the example
above. In TC, `bpf_get_hash_recalc(skb)` can also be used when SKB flow hashing
is desirable.

### Reuseport Steering Sketch

```c
SEC("sk_reuseport")
int kta_reuseport_select(struct sk_reuseport_md *ctx)
{
    __u32 h = bpf_get_prandom_u32();
    /* Production version hashes the parsed 5-tuple. */
    return h % ctx->reuseport_total;
}
```

For AF_PACKET, a practical equivalent is user-space fanout:

```cpp
int mode = PACKET_FANOUT_HASH | (fanoutGroup << 16);
setsockopt(packetFd, SOL_PACKET, PACKET_FANOUT, &mode, sizeof(mode));
```

### User-Space Reconstruction

```cpp
class TcpReassembler {
public:
    void ingest(const PacketEvent &ev) {
        auto id = canonicalStreamId(ev.key);
        auto &s = streams_[id];
        auto &side = s.side(ev.direction);

        QByteArray payload = ev.sample.mid(ev.payloadOffset, ev.payloadLength);
        if (payload.isEmpty())
            return;

        if (!side.initialized) {
            side.nextSeq = ev.seq + payload.size();
            side.initialized = true;
            s.append(ev.direction, payload);
            return;
        }

        if (seqEqual(ev.seq, side.nextSeq)) {
            s.append(ev.direction, payload);
            side.nextSeq += payload.size();
            drainOutOfOrder(s, side, ev.direction);
        } else if (seqAfter(ev.seq, side.nextSeq)) {
            side.pending.emplace(ev.seq, std::move(payload));
        } else {
            side.retransmits++;
        }

        extractContent(s);
    }

private:
    void extractContent(StreamState &s) {
        httpExtractor_.consume(s);
        smtpExtractor_.consume(s);
        smbExtractor_.consume(s);
    }

    QHash<quint64, StreamState> streams_;
    HttpExtractor httpExtractor_;
    SmtpExtractor smtpExtractor_;
    SmbExtractor smbExtractor_;
};
```

### Qt "Follow TCP Stream"

```cpp
connect(connectionsTab, &ConnectionsTab::followStreamRequested,
        streamController, &StreamController::openFollowDialog);

void StreamController::openFollowDialog(const FlowKey &key)
{
    auto stream = streamStore_.snapshot(canonicalStreamId(key));
    auto *dialog = new FollowStreamDialog(stream, parent_);
    dialog->show();
}
```

The dialog should show:

- client-to-server and server-to-client directions in distinct colors.
- ASCII/UTF-8 and hex views.
- extracted objects with content type, size, filename, and hash.
- gap markers when packets were missed or dropped.

### Throughput, Locking, and Multi-Core Scaling

Keep all segments for a stream on one worker. Use bounded memory per stream and
evict by FIN/RST, idle timeout, or byte budget. Store large extracted content on
disk or in a content-addressed cache instead of the Qt model. The GUI receives
only stream summaries until the user opens a dialog.

### Performance Gain

Compared with pure user-space raw capture, kernel annotations remove duplicate
early parsing and let worker steering preserve per-flow locality. This lowers
locking pressure and makes stream reconstruction scale with cores.

## Suggested Repository Integration Plan

1. Add a new `bpf/` target containing XDP and TC programs built with `clang
   -target bpf`.
2. Add a `daemon/` C++17 service using libbpf, AF_PACKET `TPACKET_V3`,
   optional nDPI, and shared-memory IPC.
3. Keep `kernel_module/` for Netfilter process attribution and DNS/route
   enrichment.
4. Extend `gui/core/ProcReader.cpp` with a second reader for daemon snapshots,
   leaving the existing `/proc` reader as a fallback.
5. Add Qt models for top talkers, protocol dashboards, DPI results, and TCP
   streams.
6. Add feature flags in the launcher:

```bash
./start_kta.sh --netfilter --bpf --packet-mmap --gui
```

This staged design lets the project gain XDP-level throughput without losing the
process attribution and UI foundation already implemented in the current stack.
