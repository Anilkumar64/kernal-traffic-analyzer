/**
 * @file PerfBarDelegate.h
 * @brief Delegate for rendering process TCP/UDP percentage bars.
 * @details Draws a stacked bar using sibling column data for TCP and UDP percentages.
 * @author Kernel Traffic Analyzer Project
 * @license MIT
 */
#pragma once

#include <QStyledItemDelegate>

/**
 * @brief Paints stacked TCP/UDP process share bars.
 */
class PerfBarDelegate : public QStyledItemDelegate {
    Q_OBJECT

public:
    /** @brief Constructs the delegate. @param tcpCol TCP column. @param udpCol UDP column. @param parent Optional parent. */
    explicit PerfBarDelegate(int tcpCol, int udpCol, QObject* parent = nullptr);
    /** @brief Paints the stacked bar. @param painter Painter. @param option Style option. @param index Model index. */
    void paint(QPainter* painter, const QStyleOptionViewItem& option, const QModelIndex& index) const override;

private:
    int tcp_col_{0};
    int udp_col_{0};
};
