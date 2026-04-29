#include "PacketBackend.h"

#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_vlan.h>
#include <net/if.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <poll.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <cstring>
#include <iostream>
#include <sstream>

namespace kta {
namespace {

constexpr std::uint16_t etherTypeIp = 0x0800;
constexpr std::uint16_t etherTypeIpv6 = 0x86dd;
constexpr std::uint32_t vlanHeaderLength = 4;
constexpr std::uint8_t tcpFin = 0x01;
constexpr std::uint8_t tcpSyn = 0x02;
constexpr std::uint8_t tcpRst = 0x04;
constexpr std::uint8_t tcpAck = 0x10;

bool seqBefore(std::uint32_t a, std::uint32_t b)
{
    return static_cast<std::int32_t>(a - b) < 0;
}

std::string jsonEscape(const std::string &input)
{
    std::string out;
    out.reserve(input.size() + 8);
    for (char c : input) {
        switch (c) {
        case '\\':
            out += "\\\\";
            break;
        case '"':
            out += "\\\"";
            break;
        case '\n':
            out += "\\n";
            break;
        default:
            out += c;
            break;
        }
    }
    return out;
}

std::uint16_t readBe16(const void *p)
{
    std::uint16_t v;
    std::memcpy(&v, p, sizeof(v));
    return ntohs(v);
}

std::uint32_t readBe32(const void *p)
{
    std::uint32_t v;
    std::memcpy(&v, p, sizeof(v));
    return ntohl(v);
}

} // namespace

bool FlowKey::operator==(const FlowKey &other) const
{
    return family == other.family &&
           protocol == other.protocol &&
           src == other.src &&
           dst == other.dst &&
           srcPort == other.srcPort &&
           dstPort == other.dstPort;
}

std::size_t FlowKeyHash::operator()(const FlowKey &key) const
{
    std::uint64_t h = 1469598103934665603ULL;
    auto mix = [&h](std::uint8_t b) {
        h ^= b;
        h *= 1099511628211ULL;
    };

    mix(key.family);
    mix(key.protocol);
    for (auto b : key.src)
        mix(b);
    for (auto b : key.dst)
        mix(b);
    mix(static_cast<std::uint8_t>(key.srcPort >> 8));
    mix(static_cast<std::uint8_t>(key.srcPort));
    mix(static_cast<std::uint8_t>(key.dstPort >> 8));
    mix(static_cast<std::uint8_t>(key.dstPort));
    return static_cast<std::size_t>(h);
}

PacketBackend::PacketBackend(BackendOptions options)
    : options_(std::move(options)),
      lastSnapshot_(std::chrono::steady_clock::now())
{
}

int PacketBackend::selfTest()
{
    PacketBackend backend({});

    std::vector<std::uint8_t> tcp(sizeof(struct ethhdr) + sizeof(struct iphdr) +
                                  sizeof(struct tcphdr) + 18);
    auto *eth = reinterpret_cast<struct ethhdr *>(tcp.data());
    eth->h_proto = htons(ETH_P_IP);

    auto *ip = reinterpret_cast<struct iphdr *>(tcp.data() + sizeof(struct ethhdr));
    ip->version = 4;
    ip->ihl = 5;
    ip->protocol = IPPROTO_TCP;
    ip->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr) + 18);
    inet_pton(AF_INET, "10.0.0.10", &ip->saddr);
    inet_pton(AF_INET, "93.184.216.34", &ip->daddr);

    auto *th = reinterpret_cast<struct tcphdr *>(tcp.data() + sizeof(struct ethhdr) + sizeof(struct iphdr));
    th->source = htons(51515);
    th->dest = htons(80);
    th->seq = htonl(1000);
    th->doff = 5;
    std::memcpy(tcp.data() + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr),
                "GET / HTTP/1.1\r\n\r\n", 18);

    PacketMeta tcpMeta;
    if (!backend.parsePacket(tcp.data(), tcp.size(), tcpMeta) || tcpMeta.dpiHint != DpiHint::Http) {
        std::cerr << "self-test failed: TCP/HTTP parser path\n";
        return 1;
    }
    backend.updateFlow(tcpMeta, monotonicNs());
    backend.updateStream(tcpMeta);

    std::vector<std::uint8_t> udp(sizeof(struct ethhdr) + sizeof(struct iphdr) +
                                  sizeof(struct udphdr) + 12);
    eth = reinterpret_cast<struct ethhdr *>(udp.data());
    eth->h_proto = htons(ETH_P_IP);

    ip = reinterpret_cast<struct iphdr *>(udp.data() + sizeof(struct ethhdr));
    ip->version = 4;
    ip->ihl = 5;
    ip->protocol = IPPROTO_UDP;
    ip->tot_len = htons(sizeof(struct iphdr) + sizeof(struct udphdr) + 12);
    inet_pton(AF_INET, "1.1.1.1", &ip->saddr);
    inet_pton(AF_INET, "10.0.0.10", &ip->daddr);

    auto *uh = reinterpret_cast<struct udphdr *>(udp.data() + sizeof(struct ethhdr) + sizeof(struct iphdr));
    uh->source = htons(53);
    uh->dest = htons(53000);
    uh->len = htons(sizeof(struct udphdr) + 12);

    PacketMeta udpMeta;
    if (!backend.parsePacket(udp.data(), udp.size(), udpMeta) || udpMeta.dpiHint != DpiHint::Dns) {
        std::cerr << "self-test failed: UDP/DNS parser path\n";
        return 1;
    }
    backend.updateFlow(udpMeta, monotonicNs());

    if (backend.flows_.size() != 2) {
        std::cerr << "self-test failed: expected two tracked flows\n";
        return 1;
    }

    std::cout << "kta_packet_backend self-test passed\n";
    return 0;
}

int PacketBackend::run()
{
    if (!openSocket() || !configureRing() || !bindInterface()) {
        closeSocket();
        return 1;
    }

    std::cerr << "kta_packet_backend capturing on " << options_.interfaceName
              << " with AF_PACKET TPACKET_V3\n";

    while (true) {
        pollfd pfd{};
        pfd.fd = socketFd_;
        pfd.events = POLLIN;
        poll(&pfd, 1, 100);

        consumeReadyBlocks();

        const auto now = std::chrono::steady_clock::now();
        const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - lastSnapshot_);
        if (elapsed.count() >= options_.snapshotIntervalMs) {
            printSnapshot();
            lastSnapshot_ = now;
        }
    }

    closeSocket();
    return 0;
}

bool PacketBackend::openSocket()
{
    socketFd_ = ::socket(AF_PACKET, SOCK_RAW | SOCK_NONBLOCK, htons(ETH_P_ALL));
    if (socketFd_ < 0) {
        std::cerr << "AF_PACKET socket failed: " << std::strerror(errno) << "\n";
        return false;
    }
    return true;
}

bool PacketBackend::configureRing()
{
    int version = TPACKET_V3;
    if (setsockopt(socketFd_, SOL_PACKET, PACKET_VERSION, &version, sizeof(version)) < 0) {
        std::cerr << "PACKET_VERSION failed: " << std::strerror(errno) << "\n";
        return false;
    }

    tpacket_req3 req{};
    req.tp_block_size = blockSize_;
    req.tp_frame_size = 2048;
    req.tp_block_nr = blockCount_;
    req.tp_frame_nr = (req.tp_block_size * req.tp_block_nr) / req.tp_frame_size;
    req.tp_retire_blk_tov = 64;

    if (setsockopt(socketFd_, SOL_PACKET, PACKET_RX_RING, &req, sizeof(req)) < 0) {
        std::cerr << "PACKET_RX_RING failed: " << std::strerror(errno) << "\n";
        return false;
    }

    ringSize_ = static_cast<std::size_t>(req.tp_block_size) * req.tp_block_nr;
    ring_ = mmap(nullptr, ringSize_, PROT_READ | PROT_WRITE, MAP_SHARED, socketFd_, 0);
    if (ring_ == MAP_FAILED) {
        ring_ = nullptr;
        std::cerr << "mmap packet ring failed: " << std::strerror(errno) << "\n";
        return false;
    }
    return true;
}

bool PacketBackend::bindInterface()
{
    sockaddr_ll addr{};
    addr.sll_family = AF_PACKET;
    addr.sll_protocol = htons(ETH_P_ALL);
    if (options_.interfaceName != "any") {
        addr.sll_ifindex = if_nametoindex(options_.interfaceName.c_str());
        if (addr.sll_ifindex == 0) {
            std::cerr << "unknown interface: " << options_.interfaceName << "\n";
            return false;
        }
    }

    if (bind(socketFd_, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) < 0) {
        std::cerr << "bind AF_PACKET failed: " << std::strerror(errno) << "\n";
        return false;
    }

    return true;
}

void PacketBackend::closeSocket()
{
    if (ring_) {
        munmap(ring_, ringSize_);
        ring_ = nullptr;
    }
    if (socketFd_ >= 0) {
        close(socketFd_);
        socketFd_ = -1;
    }
}

void PacketBackend::consumeReadyBlocks()
{
    if (!ring_)
        return;

    while (true) {
        auto *block = reinterpret_cast<tpacket_block_desc *>(
            static_cast<std::uint8_t *>(ring_) + static_cast<std::size_t>(currentBlock_) * blockSize_);

        if ((block->hdr.bh1.block_status & TP_STATUS_USER) == 0)
            break;

        std::uint32_t offset = block->hdr.bh1.offset_to_first_pkt;
        for (std::uint32_t i = 0; i < block->hdr.bh1.num_pkts; ++i) {
            auto *hdr = reinterpret_cast<tpacket3_hdr *>(reinterpret_cast<std::uint8_t *>(block) + offset);
            const auto *packet = reinterpret_cast<const std::uint8_t *>(hdr) + hdr->tp_mac;
            consumePacket(packet, hdr->tp_snaplen);
            offset += hdr->tp_next_offset;
        }

        block->hdr.bh1.block_status = TP_STATUS_KERNEL;
        currentBlock_ = (currentBlock_ + 1) % blockCount_;
    }
}

void PacketBackend::consumePacket(const std::uint8_t *data, std::uint32_t length)
{
    PacketMeta meta;
    if (!parsePacket(data, length, meta))
        return;

    const auto now = monotonicNs();
    updateFlow(meta, now);
    updateStream(meta);
}

bool PacketBackend::parsePacket(const std::uint8_t *data, std::uint32_t length, PacketMeta &meta) const
{
    if (length < sizeof(ethhdr))
        return false;

    std::uint32_t offset = sizeof(ethhdr);
    std::uint16_t etherType = readBe16(data + 12);

    for (int i = 0; i < 2 && (etherType == ETH_P_8021Q || etherType == ETH_P_8021AD); ++i) {
        if (length < offset + vlanHeaderLength)
            return false;
        etherType = readBe16(data + offset + 2);
        offset += vlanHeaderLength;
    }

    meta.packetLength = length;

    if (etherType == etherTypeIp) {
        if (length < offset + sizeof(iphdr))
            return false;
        const auto *ip = reinterpret_cast<const iphdr *>(data + offset);
        const std::uint8_t ihl = ip->ihl * 4;
        if (ihl < sizeof(iphdr) || length < offset + ihl)
            return false;
        if (ip->protocol != IPPROTO_TCP && ip->protocol != IPPROTO_UDP)
            return false;

        meta.key.family = AF_INET;
        meta.key.protocol = ip->protocol;
        std::memcpy(meta.key.src.data() + 12, &ip->saddr, 4);
        std::memcpy(meta.key.dst.data() + 12, &ip->daddr, 4);
        offset += ihl;
    } else if (etherType == etherTypeIpv6) {
        if (length < offset + sizeof(ip6_hdr))
            return false;
        const auto *ip6 = reinterpret_cast<const ip6_hdr *>(data + offset);
        if (ip6->ip6_nxt != IPPROTO_TCP && ip6->ip6_nxt != IPPROTO_UDP)
            return false;

        meta.key.family = AF_INET6;
        meta.key.protocol = ip6->ip6_nxt;
        std::memcpy(meta.key.src.data(), &ip6->ip6_src, 16);
        std::memcpy(meta.key.dst.data(), &ip6->ip6_dst, 16);
        offset += sizeof(ip6_hdr);
    } else {
        return false;
    }

    if (meta.key.protocol == IPPROTO_TCP) {
        if (length < offset + sizeof(tcphdr))
            return false;
        const auto *tcp = reinterpret_cast<const tcphdr *>(data + offset);
        const std::uint8_t tcpHeaderLength = tcp->doff * 4;
        if (tcpHeaderLength < sizeof(tcphdr) || length < offset + tcpHeaderLength)
            return false;

        meta.key.srcPort = ntohs(tcp->source);
        meta.key.dstPort = ntohs(tcp->dest);
        meta.tcpSeq = ntohl(tcp->seq);
        meta.tcpAck = ntohl(tcp->ack_seq);
        meta.tcpFlags = data[offset + 13];
        meta.payloadOffset = static_cast<std::uint16_t>(offset + tcpHeaderLength);
    } else {
        if (length < offset + sizeof(udphdr))
            return false;
        const auto *udp = reinterpret_cast<const udphdr *>(data + offset);
        meta.key.srcPort = ntohs(udp->source);
        meta.key.dstPort = ntohs(udp->dest);
        meta.payloadOffset = static_cast<std::uint16_t>(offset + sizeof(udphdr));
    }

    if (meta.payloadOffset > length)
        return false;
    meta.payloadLength = static_cast<std::uint16_t>(std::min<std::uint32_t>(length - meta.payloadOffset, 65535));
    meta.dpiHint = scanPayload(data + meta.payloadOffset, meta.payloadLength,
                               meta.key.protocol, meta.key.srcPort, meta.key.dstPort);
    return true;
}

void PacketBackend::updateFlow(const PacketMeta &meta, std::uint64_t nowNs)
{
    auto &flow = flows_[meta.key];
    if (flow.packets == 0)
        flow.firstSeenNs = nowNs;

    flow.packets++;
    flow.bytes += meta.packetLength;
    flow.lastSeenNs = nowNs;

    switch (meta.dpiHint) {
    case DpiHint::Http:
        flow.httpPackets++;
        break;
    case DpiHint::TlsClientHello:
        flow.tlsPackets++;
        break;
    case DpiHint::Dns:
        flow.dnsPackets++;
        break;
    case DpiHint::None:
        break;
    }
}

void PacketBackend::updateStream(const PacketMeta &meta)
{
    if (meta.key.protocol != IPPROTO_TCP || meta.payloadLength == 0)
        return;

    auto &stream = streams_[meta.key];
    auto &side = stream.client;
    auto &flow = flows_[meta.key];

    if ((meta.tcpFlags & (tcpSyn | tcpFin | tcpRst)) != 0) {
        side.initialized = false;
        side.nextSeq = 0;
    }

    if (!side.initialized) {
        side.initialized = true;
        side.nextSeq = meta.tcpSeq + meta.payloadLength;
        return;
    }

    if (meta.tcpSeq == side.nextSeq) {
        side.nextSeq += meta.payloadLength;
    } else if (seqBefore(meta.tcpSeq, side.nextSeq)) {
        flow.retransmits++;
    } else {
        flow.outOfOrder++;
        side.nextSeq = meta.tcpSeq + meta.payloadLength;
    }
}

DpiHint PacketBackend::scanPayload(const std::uint8_t *payload, std::uint16_t length,
                                   std::uint8_t protocol, std::uint16_t srcPort,
                                   std::uint16_t dstPort)
{
    if (protocol == IPPROTO_UDP && (srcPort == 53 || dstPort == 53))
        return DpiHint::Dns;

    if (length >= 4) {
        if (std::memcmp(payload, "GET ", 4) == 0 ||
            std::memcmp(payload, "POST", 4) == 0 ||
            std::memcmp(payload, "HEAD", 4) == 0 ||
            std::memcmp(payload, "PUT ", 4) == 0) {
            return DpiHint::Http;
        }
    }

    if (length >= 6 && payload[0] == 0x16 && payload[5] == 0x01)
        return DpiHint::TlsClientHello;

    return DpiHint::None;
}

std::uint64_t PacketBackend::monotonicNs()
{
    const auto now = std::chrono::steady_clock::now().time_since_epoch();
    return static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::nanoseconds>(now).count());
}

std::string PacketBackend::flowToString(const FlowKey &key)
{
    char src[INET6_ADDRSTRLEN] = {};
    char dst[INET6_ADDRSTRLEN] = {};

    if (key.family == AF_INET) {
        inet_ntop(AF_INET, key.src.data() + 12, src, sizeof(src));
        inet_ntop(AF_INET, key.dst.data() + 12, dst, sizeof(dst));
    } else {
        inet_ntop(AF_INET6, key.src.data(), src, sizeof(src));
        inet_ntop(AF_INET6, key.dst.data(), dst, sizeof(dst));
    }

    std::ostringstream out;
    out << src << ':' << key.srcPort << " -> " << dst << ':' << key.dstPort
        << '/' << (key.protocol == IPPROTO_TCP ? "TCP" : "UDP");
    return out.str();
}

std::string PacketBackend::dpiHintToString(DpiHint hint)
{
    switch (hint) {
    case DpiHint::Http:
        return "HTTP";
    case DpiHint::TlsClientHello:
        return "TLS_CLIENT_HELLO";
    case DpiHint::Dns:
        return "DNS";
    case DpiHint::None:
        return "NONE";
    }
    return "NONE";
}

void PacketBackend::printSnapshot()
{
    std::vector<std::pair<FlowKey, FlowStats>> ordered;
    ordered.reserve(flows_.size());
    for (const auto &entry : flows_)
        ordered.push_back(entry);

    std::sort(ordered.begin(), ordered.end(), [](const auto &a, const auto &b) {
        return a.second.bytes > b.second.bytes;
    });

    const auto limit = std::min<std::size_t>(ordered.size(), std::max(0, options_.maxTopFlows));
    std::uint64_t totalBytes = 0;
    std::uint64_t totalPackets = 0;
    for (const auto &entry : flows_) {
        totalBytes += entry.second.bytes;
        totalPackets += entry.second.packets;
    }

    std::cout << "{\"type\":\"kta_packet_snapshot\","
              << "\"flows\":" << flows_.size() << ','
              << "\"packets\":" << totalPackets << ','
              << "\"bytes\":" << totalBytes << ','
              << "\"top\":[";

    for (std::size_t i = 0; i < limit; ++i) {
        const auto &[key, stats] = ordered[i];
        if (i)
            std::cout << ',';

        DpiHint hint = DpiHint::None;
        if (stats.httpPackets)
            hint = DpiHint::Http;
        else if (stats.tlsPackets)
            hint = DpiHint::TlsClientHello;
        else if (stats.dnsPackets)
            hint = DpiHint::Dns;

        std::cout << "{\"flow\":\"" << jsonEscape(flowToString(key)) << "\","
                  << "\"packets\":" << stats.packets << ','
                  << "\"bytes\":" << stats.bytes << ','
                  << "\"dpi\":\"" << dpiHintToString(hint) << "\","
                  << "\"retransmits\":" << stats.retransmits << ','
                  << "\"out_of_order\":" << stats.outOfOrder << '}';
    }

    std::cout << "]}" << std::endl;
}

} // namespace kta
