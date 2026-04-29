#include "ProtoBadgeDelegate.h"
#include "../Style.h"

#include <QPainter>

ProtoBadgeDelegate::ProtoBadgeDelegate(QObject *parent) : QStyledItemDelegate(parent) {}

void ProtoBadgeDelegate::initStyleOption(QStyleOptionViewItem *option, const QModelIndex &index) const
{
    QStyledItemDelegate::initStyleOption(option, index);
    option->state &= ~QStyle::State_HasFocus;
}

QSize ProtoBadgeDelegate::sizeHint(const QStyleOptionViewItem &, const QModelIndex &) const { return {-1, 36}; }

void ProtoBadgeDelegate::paint(QPainter *p, const QStyleOptionViewItem &option, const QModelIndex &index) const
{
    QStyleOptionViewItem opt(option);
    initStyleOption(&opt, index);
    const QString text = index.data().toString().toUpper();
    p->save();
    p->fillRect(opt.rect, opt.features & QStyleOptionViewItem::Alternate ? KtaColors::BgAlt : KtaColors::BgBase);
    QColor fg = text == "UDP" ? KtaColors::Purple : KtaColors::Accent;
    QColor bg = fg;
    bg.setAlphaF(0.12);
    p->setRenderHint(QPainter::Antialiasing);
    p->setFont(uiFont(10, QFont::DemiBold));
    QRect pill(opt.rect.left() + 10, opt.rect.center().y() - 10, 44, 20);
    p->setPen(Qt::NoPen);
    p->setBrush(bg);
    p->drawRoundedRect(pill, 10, 10);
    p->setPen(fg);
    p->drawText(pill, Qt::AlignCenter, text);
    p->restore();
}
