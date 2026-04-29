#include "TtlBarDelegate.h"
#include "../Style.h"

#include <QPainter>
#include <QRegularExpression>

TtlBarDelegate::TtlBarDelegate(QObject *parent) : QStyledItemDelegate(parent) {}

void TtlBarDelegate::initStyleOption(QStyleOptionViewItem *option, const QModelIndex &index) const
{
    QStyledItemDelegate::initStyleOption(option, index);
    option->state &= ~QStyle::State_HasFocus;
}

QSize TtlBarDelegate::sizeHint(const QStyleOptionViewItem &, const QModelIndex &) const { return {-1, 36}; }

static double ttlRatio(const QString &s)
{
    if (s == "expired") return 0.0;
    QRegularExpression re("(?:(\\d+)m)?(?:(\\d+)s)?");
    auto m = re.match(s);
    int sec = m.captured(1).toInt() * 60 + m.captured(2).toInt();
    return qBound(0.0, sec / 300.0, 1.0);
}

void TtlBarDelegate::paint(QPainter *p, const QStyleOptionViewItem &option, const QModelIndex &index) const
{
    QStyleOptionViewItem opt(option);
    initStyleOption(&opt, index);
    const QString text = index.data().toString();
    p->save();
    p->fillRect(opt.rect, opt.features & QStyleOptionViewItem::Alternate ? KtaColors::BgAlt : KtaColors::BgBase);
    p->setFont(monoFont(11));
    p->setPen(KtaColors::Text2);
    QRect textRect(opt.rect.left() + 8, opt.rect.top(), opt.rect.width() - 104, opt.rect.height());
    p->drawText(textRect, Qt::AlignRight | Qt::AlignVCenter, text);
    QRectF track(opt.rect.right() - 88, opt.rect.center().y() - 1.5, 80, 3);
    p->setRenderHint(QPainter::Antialiasing);
    p->setPen(Qt::NoPen);
    p->setBrush(KtaColors::BgRaised);
    p->drawRoundedRect(track, 1.5, 1.5);
    QRectF fill = track;
    fill.setWidth(track.width() * ttlRatio(text));
    p->setBrush(KtaColors::Teal);
    p->drawRoundedRect(fill, 1.5, 1.5);
    p->restore();
}
