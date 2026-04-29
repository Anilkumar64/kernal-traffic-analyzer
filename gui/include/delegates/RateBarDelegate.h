/**
 * @file RateBarDelegate.h
 * @brief Delegate for rendering byte-rate bars.
 * @details Draws a compact horizontal magnitude bar plus formatted rate text in table cells.
 * @author Kernel Traffic Analyzer Project
 * @license MIT
 */
#pragma once

#include <QStyledItemDelegate>

/**
 * @brief Paints network rates as bars plus labels.
 */
class RateBarDelegate : public QStyledItemDelegate {
    Q_OBJECT

public:
    /** @brief Constructs the delegate. @param parent Optional parent. */
    explicit RateBarDelegate(QObject* parent = nullptr);
    /** @brief Paints a rate bar. @param painter Painter. @param option Style option. @param index Model index. */
    void paint(QPainter* painter, const QStyleOptionViewItem& option, const QModelIndex& index) const override;
};
