/**
 * @file PacketBackend.h
 * @brief AF_PACKET TPACKET_V3 packet capture backend.
 * @details Owns a raw packet socket and memory mapped RX ring, decodes IPv4 and
 * IPv6 TCP/UDP traffic, applies DPI hints, and updates the shared FlowTracker.
 * @author Kernel Traffic Analyzer Project
 * @license MIT
 */
#pragma once

#include "DpiEngine.h"
#include "FlowTracker.h"

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <linux/if_packet.h>
#include <string>
#include <thread>

class PacketBackend {
    int sock_fd_{-1};
    void* ring_{nullptr};
    size_t ring_size_{0};
    std::string iface_;
    FlowTracker& tracker_;
    DpiEngine dpi_engine_;
    std::thread capture_thread_;
    std::atomic<bool> running_{false};
    uint64_t total_packets_{0};
    uint64_t total_bytes_{0};

    static constexpr unsigned BLOCK_SIZE = 4 * 1024 * 1024;
    static constexpr unsigned FRAME_SIZE = 2048;
    static constexpr unsigned BLOCK_NR = 64;
    static constexpr unsigned FRAME_NR = (BLOCK_SIZE / FRAME_SIZE) * BLOCK_NR;

public:
    explicit PacketBackend(std::string iface, FlowTracker& tracker);
    ~PacketBackend();
    bool open();
    void start();
    void stop();
    uint64_t total_packets() const { return total_packets_; }
    uint64_t total_bytes() const { return total_bytes_; }

private:
    void run();
    void process_block(struct tpacket_block_desc* block);
    void process_frame(const uint8_t* frame_data, uint32_t frame_len,
                       const struct sockaddr_ll* addr);
    void dissect(const uint8_t* data, uint32_t len, bool is_inbound);
};
