/**
 * @file RateBarDelegate.cpp
 * @brief Implementation of byte-rate bar rendering.
 * @details Uses Qt::UserRole raw numeric values to draw capped 10 MB/s horizontal bars.
 * @author Kernel Traffic Analyzer Project
 * @license MIT
 */
#include "delegates/RateBarDelegate.h"

#include <QPainter>

namespace {
constexpr double FullScaleBytes = 10.0 * 1024.0 * 1024.0;

/**
 * @brief Returns the bar color for a rate.
 * @param rate Rate in bytes per second.
 * @return Color.
 */
QColor rateColor(quint64 rate)
{
    if (rate < 100ULL * 1024ULL) {
        return QColor("#238636");
    }
    if (rate < 1024ULL * 1024ULL) {
        return QColor("#39d353");
    }
    if (rate < 10ULL * 1024ULL * 1024ULL) {
        return QColor("#e3b341");
    }
    return QColor("#f85149");
}
}

RateBarDelegate::RateBarDelegate(QObject* parent)
    : QStyledItemDelegate(parent)
{
}

void RateBarDelegate::paint(QPainter* painter, const QStyleOptionViewItem& option, const QModelIndex& index) const
{
    if (!index.isValid()) {
        return;
    }
    const QVariant raw = index.data(Qt::UserRole);
    quint64 rate = 0;
    if (raw.canConvert<qulonglong>()) {
        rate = raw.toULongLong();
    }
    const QString text = index.data(Qt::DisplayRole).toString();

    painter->save();
    painter->setRenderHint(QPainter::Antialiasing, true);
    const QRect r = option.rect.adjusted(6, 0, -6, 0);
    QRect bar(r.left(), r.center().y() - 4, 60, 8);
    painter->setPen(Qt::NoPen);
    painter->setBrush(QColor("#21262d"));
    painter->drawRoundedRect(bar, 4, 4);
    const int fillWidth = qBound(0, static_cast<int>((static_cast<double>(rate) / FullScaleBytes) * bar.width()), bar.width());
    QRect fill = bar;
    fill.setWidth(fillWidth);
    painter->setBrush(rateColor(rate));
    painter->drawRoundedRect(fill, 4, 4);
    painter->setPen(QColor("#e6edf3"));
    painter->drawText(r.adjusted(70, 0, 0, 0), Qt::AlignVCenter | Qt::AlignLeft, text);
    painter->restore();
}
