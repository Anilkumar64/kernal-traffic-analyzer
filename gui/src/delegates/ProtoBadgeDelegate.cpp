/**
 * @file ProtoBadgeDelegate.cpp
 * @brief Implementation of protocol badge rendering.
 * @details Draws compact protocol badges with TCP, UDP, and ICMP color mapping.
 * @author Kernel Traffic Analyzer Project
 * @license MIT
 */
#include "delegates/ProtoBadgeDelegate.h"

#include <QPainter>

ProtoBadgeDelegate::ProtoBadgeDelegate(QObject* parent)
    : QStyledItemDelegate(parent)
{
}

void ProtoBadgeDelegate::paint(QPainter* painter, const QStyleOptionViewItem& option, const QModelIndex& index) const
{
    if (!index.isValid()) {
        return;
    }
    const QString proto = index.data(Qt::DisplayRole).toString().toUpper();
    QColor bg("#6e7681");
    QColor fg(Qt::white);
    if (proto == "TCP") {
        bg = QColor("#58a6ff");
    } else if (proto == "UDP") {
        bg = QColor("#39d353");
        fg = QColor(Qt::black);
    } else if (proto == "ICMP") {
        bg = QColor("#6e7681");
    }

    painter->save();
    painter->setRenderHint(QPainter::Antialiasing, true);
    QFont font = painter->font();
    font.setBold(true);
    font.setPointSize(8);
    painter->setFont(font);
    QRect badge(0, 0, 70, 20);
    badge.moveCenter(option.rect.center());
    painter->setPen(Qt::NoPen);
    painter->setBrush(bg);
    painter->drawRoundedRect(badge, 10, 10);
    painter->setPen(fg);
    painter->drawText(badge, Qt::AlignCenter, proto);
    painter->restore();
}

QSize ProtoBadgeDelegate::sizeHint(const QStyleOptionViewItem& option, const QModelIndex& index) const
{
    Q_UNUSED(option)
    Q_UNUSED(index)
    return QSize(70, 24);
}
