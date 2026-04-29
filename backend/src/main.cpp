/**
 * @file main.cpp
 * @brief Command-line entry point for the KTA packet backend.
 * @details Parses capture and export options, installs termination signal
 * handlers, starts worker threads, and prints a final capture summary.
 * @author Kernel Traffic Analyzer Project
 * @license MIT
 */
#include "JsonExporter.h"
#include "PacketBackend.h"

#include <atomic>
#include <chrono>
#include <csignal>
#include <iostream>
#include <string>
#include <thread>

namespace {

std::atomic<bool> g_running{true};

void handle_signal(int)
{
    g_running = false;
}

void print_usage(const char* program)
{
    std::cout << "Usage: " << program
              << " --iface <eth0> [--interval <secs>] [--output <path>]\n"
              << "Requires root or CAP_NET_RAW for AF_PACKET capture.\n";
}

} // namespace

int main(int argc, char** argv)
{
    std::string iface;
    int interval = 5;
    std::string output = "/tmp/kta_flows.json";

    for (int i = 1; i < argc; ++i) {
        const std::string arg = argv[i];
        if (arg == "--iface" && i + 1 < argc) {
            iface = argv[++i];
        } else if (arg == "--interval" && i + 1 < argc) {
            interval = std::stoi(argv[++i]);
        } else if (arg == "--output" && i + 1 < argc) {
            output = argv[++i];
        } else if (arg == "--help") {
            print_usage(argv[0]);
            return 0;
        } else {
            std::cerr << "unknown or incomplete argument: " << arg << "\n";
            print_usage(argv[0]);
            return 1;
        }
    }

    if (iface.empty()) {
        std::cerr << "--iface is required\n";
        print_usage(argv[0]);
        return 1;
    }

    std::signal(SIGINT, handle_signal);
    std::signal(SIGTERM, handle_signal);

    FlowTracker tracker;
    PacketBackend backend(iface, tracker);
    JsonExporter exporter(tracker, output, interval);

    if (!backend.open()) {
        return 1;
    }

    std::atomic<bool> prune_running{true};
    std::thread prune_thread([&tracker, &prune_running]() {
        constexpr uint64_t max_age_ns = 300ULL * 1000000000ULL;
        while (prune_running) {
            for (int i = 0; prune_running && i < 100; ++i) {
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
            }
            if (prune_running) {
                tracker.prune_stale(max_age_ns);
            }
        }
    });

    backend.start();
    exporter.start();

    while (g_running) {
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
    }

    backend.stop();
    exporter.stop();
    prune_running = false;
    if (prune_thread.joinable()) {
        prune_thread.join();
    }

    std::cout << "KTA backend stopped\n";
    std::cout << "total packets: " << backend.total_packets() << "\n";
    std::cout << "total bytes: " << backend.total_bytes() << "\n";
    std::cout << "flow count: " << tracker.size() << "\n";
    return 0;
}
