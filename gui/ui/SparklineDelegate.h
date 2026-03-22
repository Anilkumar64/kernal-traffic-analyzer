#include <QPainterPath>
#pragma once
#include <QStyledItemDelegate>
#include <QPainter>
#include <QVector>
#include "../core/TrafficEntry.h"

class SparklineDelegate : public QStyledItemDelegate
{
public:
    explicit SparklineDelegate(QObject *parent = nullptr)
        : QStyledItemDelegate(parent) {}

    void paint(QPainter *painter,
               const QStyleOptionViewItem &option,
               const QModelIndex &index) const override
    {
        // Get sparkline data from UserRole+1
        QVariant v = index.data(Qt::UserRole + 1);
        if (!v.isValid()) {
            QStyledItemDelegate::paint(painter, option, index);
            return;
        }

        // Draw row background
        painter->fillRect(option.rect,
            (option.state & QStyle::State_Selected)
                ? QColor("#163050")
                : (option.state & QStyle::State_MouseOver)
                    ? QColor("#131920")
                    : (index.row() % 2 == 0
                        ? QColor("#0d1117")
                        : QColor("#0f1520")));

        QVector<quint32> samples = v.value<QVector<quint32>>();
        if (samples.isEmpty()) return;

        QRect r = option.rect;
        // Sparkline area: right portion of cell
        QRect spark(r.right() - 70, r.top() + 4,
                    66, r.height() - 8);

        // Find peak for scaling
        quint32 peak = 0;
        for (auto s : samples) peak = qMax(peak, s);
        if (peak == 0) peak = 1;

        painter->save();
        painter->setRenderHint(QPainter::Antialiasing);
        painter->setClipRect(spark);

        // Draw sparkline
        QColor lineColor = index.data(Qt::ForegroundRole)
                               .value<QColor>();
        if (!lineColor.isValid())
            lineColor = QColor("#5aabff");

        QPainterPath path;
        bool first = true;
        double xStep = spark.width() / double(qMax(1, samples.size() - 1));

        for (int i = 0; i < samples.size(); ++i) {
            double x = spark.left() + i * xStep;
            double y = spark.bottom() -
                (samples[i] / double(peak)) * spark.height();
            y = qBound(double(spark.top()),
                       y, double(spark.bottom()));
            if (first) { path.moveTo(x, y); first = false; }
            else        path.lineTo(x, y);
        }

        // Fill area under sparkline
        QPainterPath fill = path;
        fill.lineTo(spark.right(), spark.bottom());
        fill.lineTo(spark.left(), spark.bottom());
        fill.closeSubpath();
        QColor fillColor = lineColor;
        fillColor.setAlpha(25);
        painter->fillPath(fill, QBrush(fillColor));

        // Draw line
        painter->setPen(QPen(lineColor, 1.2));
        painter->drawPath(path);

        // Last value dot
        if (!samples.isEmpty()) {
            double lx = spark.left() +
                (samples.size()-1) * xStep;
            double ly = spark.bottom() -
                (samples.last()/double(peak))*spark.height();
            ly = qBound(double(spark.top()),
                        ly, double(spark.bottom()));
            painter->setBrush(lineColor);
            painter->setPen(Qt::NoPen);
            painter->drawEllipse(QPointF(lx, ly), 2.5, 2.5);
        }

        painter->restore();
    }

    QSize sizeHint(const QStyleOptionViewItem &option,
                   const QModelIndex &index) const override
    {
        Q_UNUSED(option); Q_UNUSED(index);
        return QSize(80, 36);
    }
};
