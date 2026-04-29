/**
 * @file NetworkPerfTab.h
 * @brief Network performance graph tab widget.
 * @details Shows summary cards and live inbound/outbound bandwidth graphs using QPainter.
 * @author Kernel Traffic Analyzer Project
 * @license MIT
 */
#pragma once

#include "ProcReader.h"

#include <QWidget>

class QLabel;

/**
 * @brief Widget showing live network performance.
 */
class NetworkPerfTab : public QWidget {
    Q_OBJECT

public:
    /** @brief Constructs the tab. @param parent Optional parent. */
    explicit NetworkPerfTab(QWidget* parent = nullptr);
    /** @brief Updates graphs and summary cards from parsed data. @param data Current parsed data. */
    void updateFromData(const ParsedData& data);

private:
    class BandwidthGraph;

    /** @brief Builds widgets and layout. */
    void setupUi();
    /** @brief Creates a summary card. @param title Card title. @param valueLabel Output value label pointer. @return Card widget. */
    QWidget* createSummaryCard(const QString& title, QLabel** valueLabel);

    QLabel* peak_in_{nullptr};
    QLabel* peak_out_{nullptr};
    QLabel* total_in_{nullptr};
    QLabel* total_out_{nullptr};
    BandwidthGraph* inbound_graph_{nullptr};
    BandwidthGraph* outbound_graph_{nullptr};
    double peak_in_value_{0.0};
    double peak_out_value_{0.0};
    quint64 total_in_value_{0};
    quint64 total_out_value_{0};
};
