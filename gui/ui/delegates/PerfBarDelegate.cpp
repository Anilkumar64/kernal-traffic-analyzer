#include "PerfBarDelegate.h"
#include "../Style.h"

#include <QPainter>

PerfBarDelegate::PerfBarDelegate(QObject *parent) : QStyledItemDelegate(parent) {}

void PerfBarDelegate::initStyleOption(QStyleOptionViewItem *option, const QModelIndex &index) const
{
    QStyledItemDelegate::initStyleOption(option, index);
    option->state &= ~QStyle::State_HasFocus;
}

QSize PerfBarDelegate::sizeHint(const QStyleOptionViewItem &, const QModelIndex &) const { return {-1, 36}; }

void PerfBarDelegate::paint(QPainter *p, const QStyleOptionViewItem &option, const QModelIndex &index) const
{
    QStyleOptionViewItem opt(option);
    initStyleOption(&opt, index);
    const double value = index.data(Qt::UserRole).toDouble();
    QColor fill = value < 50 ? KtaColors::Teal : (value < 150 ? KtaColors::Amber : KtaColors::Red);
    p->save();
    QStyledItemDelegate::paint(p, opt, index);
    QRectF track(opt.rect.right() - 76, opt.rect.center().y() - 2, 60, 4);
    p->setRenderHint(QPainter::Antialiasing);
    p->setPen(Qt::NoPen);
    p->setBrush(KtaColors::BgRaised);
    p->drawRoundedRect(track, 2, 2);
    QRectF bar = track;
    bar.setWidth(track.width() * qBound(0.0, value / 200.0, 1.0));
    p->setBrush(fill);
    p->drawRoundedRect(bar, 2, 2);
    p->restore();
}
