/**
 * @file StateBadgeDelegate.cpp
 * @brief Implementation of state badge rendering.
 * @details Draws centered pill badges using the Kernel Traffic Analyzer state color rules.
 * @author Kernel Traffic Analyzer Project
 * @license MIT
 */
#include "delegates/StateBadgeDelegate.h"

#include <QPainter>

namespace {
/**
 * @brief Returns badge colors for a state.
 * @param state State text.
 * @return Pair of background and foreground colors.
 */
QPair<QColor, QColor> colorsForState(const QString& state)
{
    const QString normalized = state.trimmed().toUpper();
    if (normalized == "ESTABLISHED") {
        return {QColor("#238636"), Qt::white};
    }
    if (normalized == "SYN_SENT" || normalized == "SYN_RECEIVED" || normalized == "SYN_RECV") {
        return {QColor("#e3b341"), Qt::black};
    }
    if (normalized == "CLOSED") {
        return {QColor("#f85149"), Qt::white};
    }
    if (normalized == "FIN_WAIT" || normalized == "TIME_WAIT") {
        return {QColor("#8b5cf6"), Qt::white};
    }
    if (normalized == "UDP" || normalized == "UDP_ACTIVE") {
        return {QColor("#39d353"), Qt::black};
    }
    return {QColor("#6e7681"), Qt::white};
}

/**
 * @brief Paints a generic badge.
 * @param painter Painter.
 * @param rect Cell rect.
 * @param text Badge text.
 * @param bg Background.
 * @param fg Foreground.
 * @param width Width.
 */
void paintBadge(QPainter* painter, const QRect& rect, const QString& text, const QColor& bg, const QColor& fg, int width)
{
    painter->save();
    painter->setRenderHint(QPainter::Antialiasing, true);
    QFont font = painter->font();
    font.setBold(true);
    font.setPointSize(8);
    painter->setFont(font);
    const int height = 20;
    QRect badge(0, 0, width, height);
    badge.moveCenter(rect.center());
    painter->setPen(Qt::NoPen);
    painter->setBrush(bg);
    painter->drawRoundedRect(badge, height / 2.0, height / 2.0);
    painter->setPen(fg);
    painter->drawText(badge.adjusted(8, 0, -8, 0), Qt::AlignCenter, text);
    painter->restore();
}
}

StateBadgeDelegate::StateBadgeDelegate(QObject* parent)
    : QStyledItemDelegate(parent)
{
}

void StateBadgeDelegate::paint(QPainter* painter, const QStyleOptionViewItem& option, const QModelIndex& index) const
{
    if (!index.isValid()) {
        return;
    }
    const QString text = index.data(Qt::DisplayRole).toString();
    const auto colors = colorsForState(text);
    paintBadge(painter, option.rect, text, colors.first, colors.second, 96);
}

QSize StateBadgeDelegate::sizeHint(const QStyleOptionViewItem& option, const QModelIndex& index) const
{
    Q_UNUSED(option)
    Q_UNUSED(index)
    return QSize(90, 24);
}
