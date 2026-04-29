#include "StateBadgeDelegate.h"
#include "../Style.h"

#include <QPainter>

StateBadgeDelegate::StateBadgeDelegate(QObject *parent) : QStyledItemDelegate(parent) {}

void StateBadgeDelegate::initStyleOption(QStyleOptionViewItem *option, const QModelIndex &index) const
{
    QStyledItemDelegate::initStyleOption(option, index);
    option->state &= ~QStyle::State_HasFocus;
}

QSize StateBadgeDelegate::sizeHint(const QStyleOptionViewItem &, const QModelIndex &) const { return {-1, 36}; }

void StateBadgeDelegate::paint(QPainter *p, const QStyleOptionViewItem &option, const QModelIndex &index) const
{
    QStyleOptionViewItem opt(option);
    initStyleOption(&opt, index);
    const QString text = index.data().toString().toUpper();
    QColor fg = KtaColors::Text4;
    QColor bg = KtaColors::BgRaised;
    if (text == "ESTABLISHED") { fg = KtaColors::Teal; bg = KtaColors::TealD; }
    else if (text == "UDP_ACTIVE") { fg = KtaColors::Accent; bg = KtaColors::AccentD; }
    else if (text.startsWith("SYN")) { fg = KtaColors::Amber; bg = KtaColors::AmberD; }

    p->save();
    p->fillRect(opt.rect, opt.features & QStyleOptionViewItem::Alternate ? KtaColors::BgAlt : KtaColors::BgBase);
    p->setRenderHint(QPainter::Antialiasing);
    p->setFont(uiFont(10, QFont::DemiBold));
    const int w = qMin(opt.rect.width() - 16, p->fontMetrics().horizontalAdvance(text) + 18);
    QRect pill(opt.rect.left() + 8, opt.rect.center().y() - 10, w, 20);
    p->setPen(Qt::NoPen);
    p->setBrush(bg);
    p->drawRoundedRect(pill, 10, 10);
    p->setPen(fg);
    p->drawText(pill, Qt::AlignCenter, text);
    p->restore();
}
