#pragma once

#include <array>
#include <chrono>
#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

namespace kta {

enum class DpiHint : std::uint8_t {
    None = 0,
    Http = 1,
    TlsClientHello = 2,
    Dns = 3,
};

struct FlowKey {
    std::uint8_t family = 0;
    std::uint8_t protocol = 0;
    std::array<std::uint8_t, 16> src{};
    std::array<std::uint8_t, 16> dst{};
    std::uint16_t srcPort = 0;
    std::uint16_t dstPort = 0;

    bool operator==(const FlowKey &other) const;
};

struct FlowKeyHash {
    std::size_t operator()(const FlowKey &key) const;
};

struct PacketMeta {
    FlowKey key;
    std::uint32_t packetLength = 0;
    std::uint16_t payloadOffset = 0;
    std::uint16_t payloadLength = 0;
    std::uint32_t tcpSeq = 0;
    std::uint32_t tcpAck = 0;
    std::uint8_t tcpFlags = 0;
    DpiHint dpiHint = DpiHint::None;
};

struct FlowStats {
    std::uint64_t packets = 0;
    std::uint64_t bytes = 0;
    std::uint64_t httpPackets = 0;
    std::uint64_t tlsPackets = 0;
    std::uint64_t dnsPackets = 0;
    std::uint64_t retransmits = 0;
    std::uint64_t outOfOrder = 0;
    std::uint64_t firstSeenNs = 0;
    std::uint64_t lastSeenNs = 0;
};

struct BackendOptions {
    std::string interfaceName = "any";
    int snapshotIntervalMs = 1000;
    int maxTopFlows = 10;
};

class PacketBackend {
public:
    explicit PacketBackend(BackendOptions options);
    int run();
    static int selfTest();

private:
    struct StreamSide {
        bool initialized = false;
        std::uint32_t nextSeq = 0;
    };

    struct StreamState {
        StreamSide client;
        StreamSide server;
    };

    bool openSocket();
    bool configureRing();
    bool bindInterface();
    void closeSocket();
    void consumeReadyBlocks();
    void consumePacket(const std::uint8_t *data, std::uint32_t length);
    bool parsePacket(const std::uint8_t *data, std::uint32_t length, PacketMeta &meta) const;
    void updateFlow(const PacketMeta &meta, std::uint64_t nowNs);
    void updateStream(const PacketMeta &meta);
    void printSnapshot();

    static DpiHint scanPayload(const std::uint8_t *payload, std::uint16_t length,
                               std::uint8_t protocol, std::uint16_t srcPort,
                               std::uint16_t dstPort);
    static std::uint64_t monotonicNs();
    static std::string flowToString(const FlowKey &key);
    static std::string dpiHintToString(DpiHint hint);

    BackendOptions options_;
    int socketFd_ = -1;
    void *ring_ = nullptr;
    std::size_t ringSize_ = 0;
    std::uint32_t blockSize_ = 1u << 22;
    std::uint32_t blockCount_ = 16;
    std::uint32_t currentBlock_ = 0;
    std::chrono::steady_clock::time_point lastSnapshot_;

    std::unordered_map<FlowKey, FlowStats, FlowKeyHash> flows_;
    std::unordered_map<FlowKey, StreamState, FlowKeyHash> streams_;
};

} // namespace kta
