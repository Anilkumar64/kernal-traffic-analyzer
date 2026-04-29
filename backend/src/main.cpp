#include "PacketBackend.h"

#include <iostream>

int main(int argc, char **argv)
{
    kta::BackendOptions options;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if ((arg == "-i" || arg == "--interface") && i + 1 < argc) {
            options.interfaceName = argv[++i];
        } else if (arg == "--interval-ms" && i + 1 < argc) {
            options.snapshotIntervalMs = std::stoi(argv[++i]);
        } else if (arg == "--top" && i + 1 < argc) {
            options.maxTopFlows = std::stoi(argv[++i]);
        } else if (arg == "--self-test") {
            return kta::PacketBackend::selfTest();
        } else if (arg == "-h" || arg == "--help") {
            std::cout
                << "Usage: kta_packet_backend [--interface IFACE] [--interval-ms N] [--top N]\n"
                << "       kta_packet_backend --self-test\n"
                << "Requires CAP_NET_RAW or root for AF_PACKET capture.\n";
            return 0;
        }
    }

    kta::PacketBackend backend(options);
    return backend.run();
}
