#include "ColorTextDelegate.h"
#include "../Style.h"

ColorTextDelegate::ColorTextDelegate(const QColor &color, QObject *parent) : QStyledItemDelegate(parent), m_color(color) {}

void ColorTextDelegate::initStyleOption(QStyleOptionViewItem *option, const QModelIndex &index) const
{
    QStyledItemDelegate::initStyleOption(option, index);
    option->state &= ~QStyle::State_HasFocus;
    option->palette.setColor(QPalette::Text, m_color);
}

QSize ColorTextDelegate::sizeHint(const QStyleOptionViewItem &, const QModelIndex &) const { return {-1, 36}; }

void ColorTextDelegate::paint(QPainter *painter, const QStyleOptionViewItem &option, const QModelIndex &index) const
{
    QStyleOptionViewItem opt(option);
    initStyleOption(&opt, index);
    QStyledItemDelegate::paint(painter, opt, index);
}
