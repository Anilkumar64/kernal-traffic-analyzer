/**
 * @file FlowTracker.cpp
 * @brief Thread-safe flow accounting implementation.
 * @details Canonicalizes bidirectional flow keys, tracks packet and byte
 * counters, preserves first/last timestamps, and prunes idle records.
 * @author Kernel Traffic Analyzer Project
 * @license MIT
 */
#include "FlowTracker.h"

#include <algorithm>
#include <cerrno>
#include <cstring>
#include <ctime>
#include <iostream>

namespace {

uint64_t monotonic_ns()
{
    timespec ts{};
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        std::cerr << "clock_gettime(CLOCK_MONOTONIC) failed: " << std::strerror(errno) << "\n";
        return 0;
    }
    return static_cast<uint64_t>(ts.tv_sec) * 1000000000ULL + static_cast<uint64_t>(ts.tv_nsec);
}

void hash_bytes(uint32_t& hash, const void* data, size_t len)
{
    const auto* bytes = static_cast<const uint8_t*>(data);
    for (size_t i = 0; i < len; ++i) {
        hash ^= bytes[i];
        hash *= 16777619UL;
    }
}

FlowKey canonical_key(const FlowKey& key)
{
    FlowKey out = key;
    if (out.src_ip > out.dst_ip) {
        std::swap(out.src_ip, out.dst_ip);
        std::swap(out.src_port, out.dst_port);
    }
    return out;
}

} // namespace

bool FlowKey::operator==(const FlowKey& other) const
{
    return src_ip == other.src_ip && dst_ip == other.dst_ip &&
           src_port == other.src_port && dst_port == other.dst_port &&
           protocol == other.protocol;
}

size_t FlowKeyHash::operator()(const FlowKey& key) const
{
    uint32_t hash = 2166136261UL;
    hash_bytes(hash, &key.src_ip, sizeof(key.src_ip));
    hash_bytes(hash, &key.dst_ip, sizeof(key.dst_ip));
    hash_bytes(hash, &key.src_port, sizeof(key.src_port));
    hash_bytes(hash, &key.dst_port, sizeof(key.dst_port));
    hash_bytes(hash, &key.protocol, sizeof(key.protocol));
    return static_cast<size_t>(hash);
}

void FlowTracker::update(const FlowKey& key, uint32_t pkt_len, bool is_inbound,
                         uint8_t tcp_flags, DpiHint hint)
{
    const FlowKey canon = canonical_key(key);
    const uint64_t now = monotonic_ns();

    std::lock_guard<std::mutex> lock(mutex_);
    auto it = flows_.find(canon);
    if (it == flows_.end()) {
        if (flows_.size() >= MAX_FLOWS) {
            return;
        }

        FlowRecord record{};
        record.key = canon;
        record.first_seen_ns = now;
        record.last_seen_ns = now;
        record.tcp_flags_seen = tcp_flags;
        record.dpi_hint = hint;
        it = flows_.emplace(canon, record).first;
    }

    FlowRecord& record = it->second;
    if (is_inbound) {
        ++record.packets_in;
        record.bytes_in += pkt_len;
    } else {
        ++record.packets_out;
        record.bytes_out += pkt_len;
    }

    record.last_seen_ns = now;
    record.tcp_flags_seen |= tcp_flags;
    if (record.dpi_hint == DpiHint::UNKNOWN && hint != DpiHint::UNKNOWN) {
        record.dpi_hint = hint;
    }
}

std::vector<FlowRecord> FlowTracker::snapshot() const
{
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<FlowRecord> records;
    records.reserve(flows_.size());
    for (const auto& entry : flows_) {
        records.push_back(entry.second);
    }
    return records;
}

void FlowTracker::prune_stale(uint64_t max_age_ns)
{
    const uint64_t now = monotonic_ns();
    std::lock_guard<std::mutex> lock(mutex_);
    for (auto it = flows_.begin(); it != flows_.end();) {
        if (now > it->second.last_seen_ns && (now - it->second.last_seen_ns) > max_age_ns) {
            it = flows_.erase(it);
        } else {
            ++it;
        }
    }
}

size_t FlowTracker::size() const
{
    std::lock_guard<std::mutex> lock(mutex_);
    return flows_.size();
}
