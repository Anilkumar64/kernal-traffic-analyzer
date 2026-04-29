/**
 * @file NetworkPerfTab.cpp
 * @brief Implementation of the network performance tab.
 * @details Provides summary cards and custom QPainter bandwidth graphs for inbound and outbound rates.
 * @author Kernel Traffic Analyzer Project
 * @license MIT
 */
#include "tabs/NetworkPerfTab.h"

#include "Style.h"

#include <QFrame>
#include <QHBoxLayout>
#include <QLabel>
#include <QPainter>
#include <QPainterPath>
#include <QVBoxLayout>
#include <algorithm>

/**
 * @brief Custom bandwidth graph used by NetworkPerfTab.
 */
class NetworkPerfTab::BandwidthGraph : public QWidget {
public:
    /** @brief Constructs the graph. @param color Curve color. @param parent Optional parent. */
    explicit BandwidthGraph(const QColor& color, QWidget* parent = nullptr)
        : QWidget(parent),
          color_(color)
    {
        setMinimumHeight(220);
    }

    /** @brief Adds a new MB/s sample. @param mbps Sample value. */
    void addSample(double mbps)
    {
        samples_.prepend(qMax(0.0, mbps));
        while (samples_.size() > 60) {
            samples_.removeLast();
        }
        update();
    }

protected:
    /** @brief Paints the graph. @param event Paint event. */
    void paintEvent(QPaintEvent* event) override
    {
        Q_UNUSED(event)
        QPainter p(this);
        p.setRenderHint(QPainter::Antialiasing, true);
        p.fillRect(rect(), QColor(KtaColors::BgBase));
        p.setPen(QPen(QColor(KtaColors::Border), 1));
        p.drawRect(rect().adjusted(0, 0, -1, -1));

        const QRect plot = rect().adjusted(52, 16, -16, -30);
        p.setPen(QPen(QColor(KtaColors::BgElevated), 1));
        const double maxSample = samples_.isEmpty()
            ? 1.0
            : std::max(1.0, *std::max_element(samples_.cbegin(), samples_.cend()));
        const double yMax = std::max(1.0, maxSample * 1.2);
        for (int i = 0; i < 5; ++i) {
            const int y = plot.top() + (plot.height() * i / 4);
            p.drawLine(plot.left(), y, plot.right(), y);
            const double label = yMax * (1.0 - static_cast<double>(i) / 4.0);
            p.setPen(QColor(KtaColors::TextMuted));
            p.drawText(4, y - 8, 46, 16, Qt::AlignRight | Qt::AlignVCenter, QString("%1 MB/s").arg(label, 0, 'f', 1));
            p.setPen(QPen(QColor(KtaColors::BgElevated), 1));
        }
        p.setPen(QColor(KtaColors::TextMuted));
        p.drawText(plot.left(), rect().bottom() - 22, 80, 18, Qt::AlignLeft, "60s ago");
        p.drawText(plot.center().x() - 40, rect().bottom() - 22, 80, 18, Qt::AlignCenter, "30s ago");
        p.drawText(plot.right() - 50, rect().bottom() - 22, 50, 18, Qt::AlignRight, "now");

        if (samples_.isEmpty()) {
            return;
        }

        QPainterPath line;
        QPainterPath fill;
        auto pointFor = [&plot, yMax, this](int sampleIndex) {
            const double xStep = plot.width() / 59.0;
            const double x = plot.right() - (sampleIndex * xStep);
            const double y = plot.bottom() - (qBound(0.0, samples_.at(sampleIndex) / yMax, 1.0) * plot.height());
            return QPointF(x, y);
        };
        const QPointF first = pointFor(samples_.size() - 1);
        line.moveTo(first);
        fill.moveTo(first.x(), plot.bottom());
        fill.lineTo(first);
        for (int i = samples_.size() - 2; i >= 0; --i) {
            const QPointF pt = pointFor(i);
            line.lineTo(pt);
            fill.lineTo(pt);
        }
        const QPointF newest = pointFor(0);
        fill.lineTo(newest.x(), plot.bottom());
        fill.closeSubpath();

        QColor area = color_;
        area.setAlphaF(0.60);
        p.fillPath(fill, area);
        p.setPen(QPen(color_, 2));
        p.drawPath(line);
    }

private:
    QVector<double> samples_;
    QColor color_;
};

NetworkPerfTab::NetworkPerfTab(QWidget* parent)
    : QWidget(parent)
{
    setupUi();
}

void NetworkPerfTab::updateFromData(const ParsedData& data)
{
    quint64 rateIn = 0;
    quint64 rateOut = 0;
    quint64 totalIn = 0;
    quint64 totalOut = 0;
    for (const ProcRecord& proc : data.processes) {
        rateIn += proc.rateIn;
        rateOut += proc.rateOut;
        totalIn += proc.totalIn;
        totalOut += proc.totalOut;
    }
    const double inMbps = static_cast<double>(rateIn) / (1024.0 * 1024.0);
    const double outMbps = static_cast<double>(rateOut) / (1024.0 * 1024.0);
    peak_in_value_ = std::max(peak_in_value_, inMbps);
    peak_out_value_ = std::max(peak_out_value_, outMbps);
    total_in_value_ = totalIn;
    total_out_value_ = totalOut;
    peak_in_->setText(formatRate(static_cast<quint64>(peak_in_value_ * 1024.0 * 1024.0)));
    peak_out_->setText(formatRate(static_cast<quint64>(peak_out_value_ * 1024.0 * 1024.0)));
    total_in_->setText(formatBytes(total_in_value_));
    total_out_->setText(formatBytes(total_out_value_));
    inbound_graph_->addSample(inMbps);
    outbound_graph_->addSample(outMbps);
}

void NetworkPerfTab::setupUi()
{
    auto* root = new QVBoxLayout(this);
    root->setContentsMargins(12, 12, 12, 12);
    root->setSpacing(12);

    auto* cards = new QHBoxLayout();
    cards->setSpacing(10);
    cards->addWidget(createSummaryCard("Peak In", &peak_in_));
    cards->addWidget(createSummaryCard("Peak Out", &peak_out_));
    cards->addWidget(createSummaryCard("Total In", &total_in_));
    cards->addWidget(createSummaryCard("Total Out", &total_out_));
    root->addLayout(cards);

    inbound_graph_ = new BandwidthGraph(QColor(KtaColors::Accent), this);
    outbound_graph_ = new BandwidthGraph(QColor(KtaColors::Blue), this);
    root->addWidget(inbound_graph_, 1);
    root->addWidget(outbound_graph_, 1);
}

QWidget* NetworkPerfTab::createSummaryCard(const QString& title, QLabel** valueLabel)
{
    auto* frame = new QFrame(this);
    frame->setObjectName("Card");
    frame->setProperty("card", true);
    auto* layout = new QVBoxLayout(frame);
    layout->setContentsMargins(14, 10, 14, 10);
    auto* titleLabel = new QLabel(title, frame);
    titleLabel->setProperty("muted", true);
    auto* value = new QLabel("0 B/s", frame);
    value->setProperty("accent", true);
    layout->addWidget(titleLabel);
    layout->addWidget(value);
    *valueLabel = value;
    return frame;
}
