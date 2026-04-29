/**
 * @file StateBadgeDelegate.h
 * @brief Delegate for drawing connection state badges.
 * @details Paints rounded pill badges with state-specific colors in connection table cells.
 * @author Kernel Traffic Analyzer Project
 * @license MIT
 */
#pragma once

#include <QStyledItemDelegate>

/**
 * @brief Paints connection state strings as colored badges.
 */
class StateBadgeDelegate : public QStyledItemDelegate {
    Q_OBJECT

public:
    /** @brief Constructs the delegate. @param parent Optional parent. */
    explicit StateBadgeDelegate(QObject* parent = nullptr);
    /** @brief Paints a custom state badge. @param painter Painter. @param option Style option. @param index Model index. */
    void paint(QPainter* painter, const QStyleOptionViewItem& option, const QModelIndex& index) const override;
    /** @brief Returns badge size hint. @param option Style option. @param index Model index. @return Preferred size. */
    QSize sizeHint(const QStyleOptionViewItem& option, const QModelIndex& index) const override;
};
