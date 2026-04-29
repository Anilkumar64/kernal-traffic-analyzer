#include "MonoDelegate.h"
#include "../Style.h"

MonoDelegate::MonoDelegate(const QColor &color, QObject *parent) : QStyledItemDelegate(parent), m_color(color) {}

void MonoDelegate::initStyleOption(QStyleOptionViewItem *option, const QModelIndex &index) const
{
    QStyledItemDelegate::initStyleOption(option, index);
    option->state &= ~QStyle::State_HasFocus;
    option->font = monoFont(12);
    option->palette.setColor(QPalette::Text, m_color);
}

QSize MonoDelegate::sizeHint(const QStyleOptionViewItem &, const QModelIndex &) const { return {-1, 36}; }

void MonoDelegate::paint(QPainter *painter, const QStyleOptionViewItem &option, const QModelIndex &index) const
{
    QStyleOptionViewItem opt(option);
    initStyleOption(&opt, index);
    QStyledItemDelegate::paint(painter, opt, index);
}
