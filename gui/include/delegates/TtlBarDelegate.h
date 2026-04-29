/**
 * @file TtlBarDelegate.h
 * @brief Delegate for rendering TTL remaining bars.
 * @details Paints a compact fraction bar that fades from green to amber to red as time-to-live decreases.
 * @author Kernel Traffic Analyzer Project
 * @license MIT
 */
#pragma once

#include <QStyledItemDelegate>

/**
 * @brief Paints TTL remaining as a colored fraction bar.
 */
class TtlBarDelegate : public QStyledItemDelegate {
    Q_OBJECT

public:
    /** @brief Constructs the delegate. @param maxTtl Maximum TTL value. @param parent Optional parent. */
    explicit TtlBarDelegate(int maxTtl = 300, QObject* parent = nullptr);
    /** @brief Paints the TTL bar. @param painter Painter. @param option Style option. @param index Model index. */
    void paint(QPainter* painter, const QStyleOptionViewItem& option, const QModelIndex& index) const override;

private:
    int max_ttl_{300};
};
