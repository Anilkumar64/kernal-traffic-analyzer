/**
 * @file PacketBackend.cpp
 * @brief AF_PACKET capture backend implementation.
 * @details Configures a TPACKET_V3 RX ring, consumes ready blocks on a worker
 * thread, decodes Ethernet/IP/TCP/UDP frames, and feeds normalized flow records.
 * @author Kernel Traffic Analyzer Project
 * @license MIT
 */
#include "PacketBackend.h"

#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <net/if.h>
#include <poll.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>
#include <iostream>
#include <utility>

namespace {

constexpr uint16_t ETHERTYPE_IPV4 = 0x0800;
constexpr uint16_t ETHERTYPE_IPV6 = 0x86DD;
constexpr uint16_t ETHERTYPE_VLAN = 0x8100;
constexpr uint32_t ETHERNET_HEADER_LEN = 14;
constexpr uint32_t VLAN_TAG_LEN = 4;
constexpr uint8_t IPV6_EXT_HOP = 0;
constexpr uint8_t IPV6_EXT_ROUTING = 43;
constexpr uint8_t IPV6_EXT_FRAGMENT = 44;
constexpr uint8_t IPV6_EXT_AH = 51;
constexpr uint8_t IPV6_EXT_DEST = 60;

uint16_t read_be16(const void* ptr)
{
    uint16_t value{};
    std::memcpy(&value, ptr, sizeof(value));
    return ntohs(value);
}

uint32_t ipv6_tail32(const in6_addr& addr)
{
    uint32_t value{};
    std::memcpy(&value, &addr.s6_addr[12], sizeof(value));
    return value;
}

bool is_ipv6_extension(uint8_t next_header)
{
    return next_header == IPV6_EXT_HOP || next_header == IPV6_EXT_ROUTING ||
           next_header == IPV6_EXT_FRAGMENT || next_header == IPV6_EXT_AH ||
           next_header == IPV6_EXT_DEST;
}

} // namespace

PacketBackend::PacketBackend(std::string iface, FlowTracker& tracker)
    : iface_(std::move(iface)),
      tracker_(tracker)
{
}

PacketBackend::~PacketBackend()
{
    stop();
    if (ring_ != nullptr) {
        if (munmap(ring_, ring_size_) != 0) {
            std::cerr << "munmap packet ring failed: " << std::strerror(errno) << "\n";
        }
        ring_ = nullptr;
    }
    if (sock_fd_ >= 0) {
        if (close(sock_fd_) != 0) {
            std::cerr << "close packet socket failed: " << std::strerror(errno) << "\n";
        }
        sock_fd_ = -1;
    }
}

bool PacketBackend::open()
{
    sock_fd_ = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock_fd_ < 0) {
        std::cerr << "socket(AF_PACKET) failed: " << std::strerror(errno) << "\n";
        return false;
    }

    int version = TPACKET_V3;
    if (setsockopt(sock_fd_, SOL_PACKET, PACKET_VERSION, &version, sizeof(version)) != 0) {
        std::cerr << "setsockopt(PACKET_VERSION) failed: " << std::strerror(errno) << "\n";
        return false;
    }

    tpacket_req3 req{};
    req.tp_block_size = BLOCK_SIZE;
    req.tp_block_nr = BLOCK_NR;
    req.tp_frame_size = FRAME_SIZE;
    req.tp_frame_nr = FRAME_NR;
    req.tp_retire_blk_tov = 60;
    req.tp_feature_req_word = TP_FT_REQ_FILL_RXHASH;

    if (setsockopt(sock_fd_, SOL_PACKET, PACKET_RX_RING, &req, sizeof(req)) != 0) {
        std::cerr << "setsockopt(PACKET_RX_RING) failed: " << std::strerror(errno) << "\n";
        return false;
    }

    ring_size_ = static_cast<size_t>(BLOCK_SIZE) * BLOCK_NR;
    ring_ = mmap(nullptr, ring_size_, PROT_READ | PROT_WRITE,
                 MAP_SHARED | MAP_LOCKED, sock_fd_, 0);
    if (ring_ == MAP_FAILED) {
        ring_ = nullptr;
        std::cerr << "mmap packet ring failed: " << std::strerror(errno) << "\n";
        return false;
    }

    sockaddr_ll addr{};
    addr.sll_family = AF_PACKET;
    addr.sll_protocol = htons(ETH_P_ALL);
    addr.sll_ifindex = static_cast<int>(if_nametoindex(iface_.c_str()));
    if (addr.sll_ifindex == 0) {
        std::cerr << "if_nametoindex(" << iface_ << ") failed: " << std::strerror(errno) << "\n";
        return false;
    }

    if (bind(sock_fd_, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
        std::cerr << "bind(AF_PACKET) failed: " << std::strerror(errno) << "\n";
        return false;
    }

    return true;
}

void PacketBackend::start()
{
    bool expected = false;
    if (running_.compare_exchange_strong(expected, true)) {
        capture_thread_ = std::thread(&PacketBackend::run, this);
    }
}

void PacketBackend::stop()
{
    running_ = false;
    if (capture_thread_.joinable()) {
        capture_thread_.join();
    }
}

void PacketBackend::run()
{
    pollfd pfd{};
    pfd.fd = sock_fd_;
    pfd.events = POLLIN;

    while (running_) {
        const int rc = poll(&pfd, 1, 100);
        if (rc < 0) {
            if (errno == EINTR) {
                continue;
            }
            std::cerr << "poll packet ring failed: " << std::strerror(errno) << "\n";
            break;
        }

        for (unsigned i = 0; i < BLOCK_NR; ++i) {
            auto* block = reinterpret_cast<tpacket_block_desc*>(
                static_cast<uint8_t*>(ring_) + (static_cast<size_t>(i) * BLOCK_SIZE));
            if ((block->hdr.bh1.block_status & TP_STATUS_USER) != 0U) {
                process_block(block);
                block->hdr.bh1.block_status = TP_STATUS_KERNEL;
            }
        }
    }
}

void PacketBackend::process_block(tpacket_block_desc* block)
{
    uint32_t offset = block->hdr.bh1.offset_to_first_pkt;
    for (uint32_t i = 0; i < block->hdr.bh1.num_pkts; ++i) {
        auto* hdr = reinterpret_cast<tpacket3_hdr*>(static_cast<uint8_t*>(static_cast<void*>(block)) + offset);
        const auto* addr = reinterpret_cast<const sockaddr_ll*>(
            reinterpret_cast<const uint8_t*>(hdr) + TPACKET_ALIGN(sizeof(tpacket3_hdr)));
        const auto* data = reinterpret_cast<const uint8_t*>(hdr) + hdr->tp_mac;
        process_frame(data, hdr->tp_snaplen, addr);
        offset += hdr->tp_next_offset;
        if (hdr->tp_next_offset == 0) {
            break;
        }
    }
}

void PacketBackend::process_frame(const uint8_t* frame_data, uint32_t frame_len,
                                  const sockaddr_ll* addr)
{
    if (frame_data == nullptr || frame_len == 0) {
        return;
    }

    ++total_packets_;
    total_bytes_ += frame_len;

    bool inbound = true;
    if (addr != nullptr && addr->sll_pkttype == PACKET_OUTGOING) {
        inbound = false;
    }
    dissect(frame_data, frame_len, inbound);
}

void PacketBackend::dissect(const uint8_t* data, uint32_t len, bool is_inbound)
{
    (void)dpi_engine_;
    if (data == nullptr || len < ETHERNET_HEADER_LEN) {
        return;
    }

    uint32_t offset = ETHERNET_HEADER_LEN;
    uint16_t ethertype = read_be16(data + 12);
    if (ethertype == ETHERTYPE_VLAN) {
        if (len < ETHERNET_HEADER_LEN + VLAN_TAG_LEN) {
            return;
        }
        ethertype = read_be16(data + 16);
        offset += VLAN_TAG_LEN;
    }

    uint32_t src_ip = 0;
    uint32_t dst_ip = 0;
    uint8_t protocol = 0;

    if (ethertype == ETHERTYPE_IPV4) {
        if (len < offset + sizeof(iphdr)) {
            return;
        }
        const auto* ip = reinterpret_cast<const iphdr*>(data + offset);
        const uint32_t ihl = static_cast<uint32_t>(ip->ihl) * 4U;
        if (ip->version != 4 || ihl < sizeof(iphdr) || len < offset + ihl) {
            return;
        }
        src_ip = ip->saddr;
        dst_ip = ip->daddr;
        protocol = ip->protocol;
        offset += ihl;
    } else if (ethertype == ETHERTYPE_IPV6) {
        if (len < offset + sizeof(ipv6hdr)) {
            return;
        }
        const auto* ip6 = reinterpret_cast<const ipv6hdr*>(data + offset);
        src_ip = ipv6_tail32(ip6->saddr);
        dst_ip = ipv6_tail32(ip6->daddr);
        protocol = ip6->nexthdr;
        offset += sizeof(ipv6hdr);

        for (int i = 0; i < 8 && is_ipv6_extension(protocol); ++i) {
            if (protocol == IPV6_EXT_FRAGMENT) {
                if (len < offset + 8) {
                    return;
                }
                protocol = data[offset];
                offset += 8;
                continue;
            }

            if (len < offset + 2) {
                return;
            }
            const uint8_t next = data[offset];
            uint32_t ext_len = 0;
            if (protocol == IPV6_EXT_AH) {
                ext_len = static_cast<uint32_t>(data[offset + 1] + 2U) * 4U;
            } else {
                ext_len = static_cast<uint32_t>(data[offset + 1] + 1U) * 8U;
            }
            if (ext_len == 0 || len < offset + ext_len) {
                return;
            }
            protocol = next;
            offset += ext_len;
        }
    } else {
        return;
    }

    uint16_t src_port = 0;
    uint16_t dst_port = 0;
    uint8_t tcp_flags = 0;
    const uint8_t* payload = nullptr;
    size_t payload_len = 0;

    if (protocol == IPPROTO_TCP) {
        if (len < offset + sizeof(tcphdr)) {
            return;
        }
        src_port = read_be16(data + offset);
        dst_port = read_be16(data + offset + 2);
        const uint32_t tcp_hlen = static_cast<uint32_t>(data[offset + 12] >> 4U) * 4U;
        if (tcp_hlen < sizeof(tcphdr) || len < offset + tcp_hlen) {
            return;
        }
        tcp_flags = data[offset + 13];
        payload = data + offset + tcp_hlen;
        payload_len = len - offset - tcp_hlen;
    } else if (protocol == IPPROTO_UDP) {
        if (len < offset + sizeof(udphdr)) {
            return;
        }
        src_port = read_be16(data + offset);
        dst_port = read_be16(data + offset + 2);
        payload = data + offset + sizeof(udphdr);
        payload_len = len - offset - sizeof(udphdr);
    } else {
        return;
    }

    const bool port_inbound = dst_port < 1024 ? true : is_inbound;
    FlowKey key{src_ip, dst_ip, src_port, dst_port, protocol};
    const DpiHint hint = DpiEngine::inspect(payload, payload_len, dst_port, src_port);
    tracker_.update(key, len, port_inbound, tcp_flags, hint);
}
