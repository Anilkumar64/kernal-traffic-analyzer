/**
 * @file JsonExporter.h
 * @brief Periodic JSON snapshot writer for flow records.
 * @details Runs a background export loop that serializes FlowTracker snapshots
 * into hand-rolled JSON for standalone use and GUI ingestion.
 * @author Kernel Traffic Analyzer Project
 * @license MIT
 */
#pragma once

#include "FlowTracker.h"

#include <atomic>
#include <string>
#include <thread>
#include <vector>

class JsonExporter {
    std::string output_path_;
    int interval_secs_;
    std::thread export_thread_;
    std::atomic<bool> running_{false};
    const FlowTracker& tracker_;

public:
    JsonExporter(const FlowTracker& tracker, std::string path, int interval_secs);
    void start();
    void stop();

private:
    void run();
    std::string serialize(const std::vector<FlowRecord>& records) const;
};
