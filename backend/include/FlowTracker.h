/**
 * @file FlowTracker.h
 * @brief In-memory flow accounting for captured packets.
 * @details Provides canonical flow keys, FNV-1a hashing, and thread-safe flow
 * snapshots consumed by the backend JSON exporter and future GUI components.
 * @author Kernel Traffic Analyzer Project
 * @license MIT
 */
#pragma once

#include <cstddef>
#include <cstdint>
#include <mutex>
#include <unordered_map>
#include <vector>

struct FlowKey {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t protocol;

    bool operator==(const FlowKey& other) const;
};

struct FlowKeyHash {
    size_t operator()(const FlowKey& key) const;
};

enum class DpiHint { UNKNOWN, DNS, HTTP, TLS, OTHER };

struct FlowRecord {
    FlowKey key;
    uint64_t packets_in;
    uint64_t packets_out;
    uint64_t bytes_in;
    uint64_t bytes_out;
    uint64_t first_seen_ns;
    uint64_t last_seen_ns;
    uint8_t tcp_flags_seen;
    DpiHint dpi_hint;
};

class FlowTracker {
    std::unordered_map<FlowKey, FlowRecord, FlowKeyHash> flows_;
    mutable std::mutex mutex_;
    static constexpr size_t MAX_FLOWS = 131072;

public:
    void update(const FlowKey& key, uint32_t pkt_len, bool is_inbound,
                uint8_t tcp_flags, DpiHint hint);
    std::vector<FlowRecord> snapshot() const;
    void prune_stale(uint64_t max_age_ns);
    size_t size() const;
};
