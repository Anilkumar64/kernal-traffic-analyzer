/**
 * @file PerfBarDelegate.cpp
 * @brief Implementation of stacked process protocol bars.
 * @details Reads TCP and UDP percentages from sibling model indexes and paints a fixed-width stacked bar.
 * @author Kernel Traffic Analyzer Project
 * @license MIT
 */
#include "delegates/PerfBarDelegate.h"

#include <QPainter>

PerfBarDelegate::PerfBarDelegate(int tcpCol, int udpCol, QObject* parent)
    : QStyledItemDelegate(parent),
      tcp_col_(tcpCol),
      udp_col_(udpCol)
{
}

void PerfBarDelegate::paint(QPainter* painter, const QStyleOptionViewItem& option, const QModelIndex& index) const
{
    if (!index.isValid()) {
        return;
    }
    const QModelIndex tcpIndex = index.sibling(index.row(), tcp_col_);
    const QModelIndex udpIndex = index.sibling(index.row(), udp_col_);
    double tcp = 0.0;
    double udp = 0.0;
    const QVariant tcpRaw = tcpIndex.data(Qt::UserRole);
    const QVariant udpRaw = udpIndex.data(Qt::UserRole);
    if (tcpRaw.canConvert<double>()) {
        tcp = tcpRaw.toDouble();
    }
    if (udpRaw.canConvert<double>()) {
        udp = udpRaw.toDouble();
    }
    tcp = qBound(0.0, tcp, 100.0);
    udp = qBound(0.0, udp, 100.0);

    painter->save();
    painter->setRenderHint(QPainter::Antialiasing, true);
    QRect bar = option.rect.adjusted(8, 9, -8, -9);
    if (bar.height() < 8) {
        bar.setHeight(8);
        bar.moveCenter(option.rect.center());
    }
    painter->setPen(Qt::NoPen);
    painter->setBrush(QColor("#21262d"));
    painter->drawRoundedRect(bar, 4, 4);
    const int tcpWidth = static_cast<int>((tcp / 100.0) * bar.width());
    const int udpWidth = static_cast<int>((udp / 100.0) * bar.width());
    QRect tcpRect = bar;
    tcpRect.setWidth(qMin(tcpWidth, bar.width()));
    painter->setBrush(QColor("#58a6ff"));
    painter->drawRoundedRect(tcpRect, 4, 4);
    QRect udpRect = bar;
    udpRect.setLeft(tcpRect.right() + 1);
    udpRect.setWidth(qMin(udpWidth, qMax(0, bar.right() - udpRect.left() + 1)));
    painter->setBrush(QColor("#39d353"));
    painter->drawRoundedRect(udpRect, 4, 4);
    painter->setPen(QColor("#e6edf3"));
    painter->drawText(option.rect.adjusted(8, 0, -8, 0), Qt::AlignCenter, index.data(Qt::DisplayRole).toString());
    painter->restore();
}
