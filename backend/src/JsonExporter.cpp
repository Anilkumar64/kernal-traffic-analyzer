/**
 * @file JsonExporter.cpp
 * @brief JSON flow snapshot exporter.
 * @details Periodically reads FlowTracker snapshots and writes a compact
 * hand-rolled JSON document with ISO-8601 metadata and dotted IPv4 addresses.
 * @author Kernel Traffic Analyzer Project
 * @license MIT
 */
#include "JsonExporter.h"

#include <arpa/inet.h>

#include <chrono>
#include <ctime>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <utility>

namespace {

std::string dpi_to_string(DpiHint hint)
{
    switch (hint) {
    case DpiHint::DNS:
        return "DNS";
    case DpiHint::HTTP:
        return "HTTP";
    case DpiHint::TLS:
        return "TLS";
    case DpiHint::OTHER:
        return "OTHER";
    case DpiHint::UNKNOWN:
    default:
        return "UNKNOWN";
    }
}

std::string ip_to_string(uint32_t ip)
{
    char buf[INET_ADDRSTRLEN]{};
    in_addr addr{};
    addr.s_addr = ip;
    if (inet_ntop(AF_INET, &addr, buf, sizeof(buf)) == nullptr) {
        return "0.0.0.0";
    }
    return std::string(buf);
}

std::string iso8601_now()
{
    const std::time_t now = std::time(nullptr);
    std::tm tm{};
    if (gmtime_r(&now, &tm) == nullptr) {
        return "1970-01-01T00:00:00Z";
    }
    std::ostringstream out;
    out << std::put_time(&tm, "%Y-%m-%dT%H:%M:%SZ");
    return out.str();
}

} // namespace

JsonExporter::JsonExporter(const FlowTracker& tracker, std::string path, int interval_secs)
    : output_path_(std::move(path)),
      interval_secs_(interval_secs > 0 ? interval_secs : 5),
      tracker_(tracker)
{
}

void JsonExporter::start()
{
    bool expected = false;
    if (running_.compare_exchange_strong(expected, true)) {
        export_thread_ = std::thread(&JsonExporter::run, this);
    }
}

void JsonExporter::stop()
{
    running_ = false;
    if (export_thread_.joinable()) {
        export_thread_.join();
    }

    std::ofstream out(output_path_, std::ios::trunc);
    if (!out) {
        std::cerr << "failed to open JSON export path " << output_path_ << "\n";
        return;
    }
    out << serialize(tracker_.snapshot());
    if (!out) {
        std::cerr << "failed to write final JSON snapshot to " << output_path_ << "\n";
    }
}

void JsonExporter::run()
{
    while (running_) {
        std::ofstream out(output_path_, std::ios::trunc);
        if (!out) {
            std::cerr << "failed to open JSON export path " << output_path_ << "\n";
        } else {
            out << serialize(tracker_.snapshot());
            if (!out) {
                std::cerr << "failed to write JSON snapshot to " << output_path_ << "\n";
            }
        }

        for (int i = 0; running_ && i < interval_secs_ * 10; ++i) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
    }
}

std::string JsonExporter::serialize(const std::vector<FlowRecord>& records) const
{
    std::ostringstream out;
    out << "{\n";
    out << "  \"metadata\": {\n";
    out << "    \"generated_at\": \"" << iso8601_now() << "\",\n";
    out << "    \"flow_count\": " << records.size() << ",\n";
    out << "    \"exporter_version\": \"1.0.0\"\n";
    out << "  },\n";
    out << "  \"flows\": [\n";

    for (size_t i = 0; i < records.size(); ++i) {
        const FlowRecord& r = records[i];
        out << "    {\n";
        out << "      \"src_ip\": \"" << ip_to_string(r.key.src_ip) << "\", "
            << "\"dst_ip\": \"" << ip_to_string(r.key.dst_ip) << "\",\n";
        out << "      \"src_port\": " << r.key.src_port << ", "
            << "\"dst_port\": " << r.key.dst_port << ", "
            << "\"protocol\": " << static_cast<unsigned>(r.key.protocol) << ",\n";
        out << "      \"packets_in\": " << r.packets_in << ", "
            << "\"packets_out\": " << r.packets_out << ",\n";
        out << "      \"bytes_in\": " << r.bytes_in << ", "
            << "\"bytes_out\": " << r.bytes_out << ",\n";
        out << "      \"first_seen_ns\": " << r.first_seen_ns << ", "
            << "\"last_seen_ns\": " << r.last_seen_ns << ",\n";
        out << "      \"tcp_flags\": " << static_cast<unsigned>(r.tcp_flags_seen) << ", "
            << "\"dpi_hint\": \"" << dpi_to_string(r.dpi_hint) << "\"\n";
        out << "    }";
        if (i + 1 < records.size()) {
            out << ",";
        }
        out << "\n";
    }

    out << "  ]\n";
    out << "}\n";
    return out.str();
}
