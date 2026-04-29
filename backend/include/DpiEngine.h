/**
 * @file DpiEngine.h
 * @brief Lightweight packet payload classifier.
 * @details Implements bounds-safe protocol hints for DNS, HTTP, and TLS using
 * small prefix and port checks suitable for the AF_PACKET backend fast path.
 * @author Kernel Traffic Analyzer Project
 * @license MIT
 */
#pragma once

#include "FlowTracker.h"

#include <cstddef>
#include <cstdint>

class DpiEngine {
public:
    static DpiHint inspect(const uint8_t* payload, size_t len, uint16_t dst_port,
                           uint16_t src_port);

private:
    static bool is_dns(const uint8_t* p, size_t len, uint16_t sport, uint16_t dport);
    static bool is_http(const uint8_t* p, size_t len);
    static bool is_tls(const uint8_t* p, size_t len);
};
