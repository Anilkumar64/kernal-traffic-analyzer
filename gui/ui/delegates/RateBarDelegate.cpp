#include "RateBarDelegate.h"
#include "../Style.h"

#include <QPainter>
#include <QRegularExpression>

RateBarDelegate::RateBarDelegate(const QColor &fill, QObject *parent) : QStyledItemDelegate(parent), m_fill(fill) {}

void RateBarDelegate::initStyleOption(QStyleOptionViewItem *option, const QModelIndex &index) const
{
    QStyledItemDelegate::initStyleOption(option, index);
    option->state &= ~QStyle::State_HasFocus;
}

QSize RateBarDelegate::sizeHint(const QStyleOptionViewItem &, const QModelIndex &) const { return {-1, 36}; }

static double rateRatio(const QString &s)
{
    if (s == "-") return 0.0;
    QRegularExpression re("([0-9.]+)\\s*([KMG]?B/s)");
    auto m = re.match(s);
    if (!m.hasMatch()) return 0.0;
    double v = m.captured(1).toDouble();
    const QString u = m.captured(2);
    if (u.startsWith("K")) v *= 1024.0;
    else if (u.startsWith("M")) v *= 1024.0 * 1024.0;
    else if (u.startsWith("G")) v *= 1024.0 * 1024.0 * 1024.0;
    return qBound(0.0, v / (1024.0 * 1024.0), 1.0);
}

void RateBarDelegate::paint(QPainter *p, const QStyleOptionViewItem &option, const QModelIndex &index) const
{
    QStyleOptionViewItem opt(option);
    initStyleOption(&opt, index);
    const QString text = index.data().toString();
    p->save();
    p->fillRect(opt.rect, opt.features & QStyleOptionViewItem::Alternate ? KtaColors::BgAlt : KtaColors::BgBase);
    p->setFont(monoFont(12));
    p->setPen(KtaColors::Text2);
    QRect textRect = opt.rect.adjusted(6, 0, -76, 0);
    p->drawText(textRect, Qt::AlignRight | Qt::AlignVCenter, text);
    QRectF track(opt.rect.right() - 68, opt.rect.center().y() - 2, 60, 4);
    p->setRenderHint(QPainter::Antialiasing);
    p->setPen(Qt::NoPen);
    p->setBrush(KtaColors::BgRaised);
    p->drawRoundedRect(track, 2, 2);
    QRectF fill = track;
    fill.setWidth(track.width() * rateRatio(text));
    p->setBrush(m_fill);
    p->drawRoundedRect(fill, 2, 2);
    p->restore();
}
