/**
 * @file DpiEngine.cpp
 * @brief Lightweight DPI hint implementation.
 * @details Performs only bounded prefix and port checks so packet capture stays
 * predictable and safe under arbitrary payload lengths.
 * @author Kernel Traffic Analyzer Project
 * @license MIT
 */
#include "DpiEngine.h"

#include <cstring>

DpiHint DpiEngine::inspect(const uint8_t* payload, size_t len, uint16_t dst_port,
                           uint16_t src_port)
{
    if (is_dns(payload, len, src_port, dst_port)) {
        return DpiHint::DNS;
    }
    if (is_http(payload, len)) {
        return DpiHint::HTTP;
    }
    if (is_tls(payload, len)) {
        return DpiHint::TLS;
    }
    return DpiHint::UNKNOWN;
}

bool DpiEngine::is_dns(const uint8_t* p, size_t len, uint16_t sport, uint16_t dport)
{
    return p != nullptr && len >= 12 && (dport == 53 || sport == 53);
}

bool DpiEngine::is_http(const uint8_t* p, size_t len)
{
    if (p == nullptr || len < 4) {
        return false;
    }
    return std::memcmp(p, "GET ", 4) == 0 ||
           std::memcmp(p, "POST", 4) == 0 ||
           std::memcmp(p, "PUT ", 4) == 0 ||
           std::memcmp(p, "HEAD", 4) == 0 ||
           std::memcmp(p, "HTTP", 4) == 0;
}

bool DpiEngine::is_tls(const uint8_t* p, size_t len)
{
    return p != nullptr && len >= 5 && p[0] == 0x16 && p[1] == 0x03;
}
