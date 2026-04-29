/**
 * @file ProtoBadgeDelegate.h
 * @brief Delegate for drawing protocol badges.
 * @details Paints TCP, UDP, and ICMP protocol values as compact colored pills.
 * @author Kernel Traffic Analyzer Project
 * @license MIT
 */
#pragma once

#include <QStyledItemDelegate>

/**
 * @brief Paints protocol strings as colored badges.
 */
class ProtoBadgeDelegate : public QStyledItemDelegate {
    Q_OBJECT

public:
    /** @brief Constructs the delegate. @param parent Optional parent. */
    explicit ProtoBadgeDelegate(QObject* parent = nullptr);
    /** @brief Paints a protocol badge. @param painter Painter. @param option Style option. @param index Model index. */
    void paint(QPainter* painter, const QStyleOptionViewItem& option, const QModelIndex& index) const override;
    /** @brief Returns badge size hint. @param option Style option. @param index Model index. @return Preferred size. */
    QSize sizeHint(const QStyleOptionViewItem& option, const QModelIndex& index) const override;
};
