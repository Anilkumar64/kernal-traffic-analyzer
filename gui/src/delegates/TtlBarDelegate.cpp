/**
 * @file TtlBarDelegate.cpp
 * @brief Implementation of TTL fraction bar rendering.
 * @details Draws a fixed-height progress bar with green, amber, or red color based on the remaining TTL fraction.
 * @author Kernel Traffic Analyzer Project
 * @license MIT
 */
#include "delegates/TtlBarDelegate.h"

#include <QPainter>

TtlBarDelegate::TtlBarDelegate(int maxTtl, QObject* parent)
    : QStyledItemDelegate(parent),
      max_ttl_(qMax(1, maxTtl))
{
}

void TtlBarDelegate::paint(QPainter* painter, const QStyleOptionViewItem& option, const QModelIndex& index) const
{
    if (!index.isValid()) {
        return;
    }
    int ttl = 0;
    const QVariant raw = index.data(Qt::UserRole);
    if (raw.canConvert<int>()) {
        ttl = raw.toInt();
    } else {
        ttl = index.data(Qt::DisplayRole).toInt();
    }
    const double fraction = qBound(0.0, static_cast<double>(ttl) / static_cast<double>(max_ttl_), 1.0);
    QColor fill = fraction > 0.6 ? QColor("#238636") : (fraction > 0.25 ? QColor("#e3b341") : QColor("#f85149"));

    painter->save();
    painter->setRenderHint(QPainter::Antialiasing, true);
    QRect bar = option.rect.adjusted(8, 9, -8, -9);
    painter->setPen(Qt::NoPen);
    painter->setBrush(QColor("#21262d"));
    painter->drawRoundedRect(bar, 4, 4);
    QRect active = bar;
    active.setWidth(static_cast<int>(bar.width() * fraction));
    painter->setBrush(fill);
    painter->drawRoundedRect(active, 4, 4);
    painter->setPen(QColor("#e6edf3"));
    painter->drawText(option.rect.adjusted(8, 0, -8, 0), Qt::AlignCenter, QString::number(ttl));
    painter->restore();
}
