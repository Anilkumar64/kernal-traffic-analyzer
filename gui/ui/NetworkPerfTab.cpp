#include "NetworkPerfTab.h"
#include "Style.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QGridLayout>
#include <QFrame>
#include <QPainter>
#include <QPainterPath>
#include <QDateTime>
#include <QRegularExpression>
#include <QtMath>

// ================================================================
// LatencyGraph
// ================================================================
LatencyGraph::LatencyGraph(QWidget *parent) : QWidget(parent)
{
    setMinimumHeight(180);
    setStyleSheet("background:#1e1e1e;");
}

void LatencyGraph::addSample(double latencyMs, bool ok)
{
    PingResult r;
    r.ts = QDateTime::currentSecsSinceEpoch();
    r.latency = latencyMs;
    r.ok = ok;
    if (m_samples.size() >= MAX)
        m_samples.removeFirst();
    m_samples.append(r);
    update();
}

void LatencyGraph::clear()
{
    m_samples.clear();
    update();
}

double LatencyGraph::avgLatency() const
{
    double sum = 0;
    int cnt = 0;
    for (const auto &s : m_samples)
        if (s.ok)
        {
            sum += s.latency;
            cnt++;
        }
    return cnt > 0 ? sum / cnt : 0.0;
}

double LatencyGraph::packetLoss() const
{
    if (m_samples.isEmpty())
        return 0.0;
    int lost = 0;
    for (const auto &s : m_samples)
        if (!s.ok)
            lost++;
    return lost * 100.0 / m_samples.size();
}

void LatencyGraph::paintEvent(QPaintEvent *)
{
    QPainter p(this);
    p.setRenderHint(QPainter::Antialiasing);
    QRect r = rect();
    p.fillRect(r, QColor("#252526"));

    if (m_samples.isEmpty())
    {
        QFont f("Segoe UI");
        f.setPixelSize(13);
        p.setFont(f);
        p.setPen(QColor("#555555"));
        p.drawText(r, Qt::AlignCenter, "Pinging 8.8.8.8...");
        return;
    }

    // Find peak
    double peak = 1.0;
    for (const auto &s : m_samples)
        if (s.ok)
            peak = qMax(peak, s.latency);
    peak *= 1.2;

    QRect gr = r.adjusted(50, 10, -10, -24);

    // Grid
    p.setPen(QPen(QColor("#333333"), 1, Qt::DotLine));
    for (int i = 1; i < 4; ++i)
    {
        int y = gr.top() + gr.height() * i / 4;
        p.drawLine(gr.left(), y, gr.right(), y);
        QFont af("Segoe UI");
        af.setPixelSize(9);
        p.setFont(af);
        p.setPen(QColor("#8a8a8a"));
        p.drawText(QRect(gr.left() - 48, y - 8, 44, 16),
                   Qt::AlignRight | Qt::AlignVCenter,
                   QString("%1ms").arg(peak * (4 - i) / 4, 0, 'f', 0));
        p.setPen(QPen(QColor("#333333"), 1, Qt::DotLine));
    }

    double xStep = gr.width() / double(qMax(1, MAX - 1));

    // Draw latency line
    QPainterPath path;
    bool first = true;
    for (int i = 0; i < m_samples.size(); ++i)
    {
        const PingResult &s = m_samples[i];
        double x = gr.left() + (MAX - m_samples.size() + i) * xStep;
        if (!s.ok)
        {
            // Draw timeout marker
            p.setPen(QPen(QColor("#ef4444"), 1));
            p.drawLine(int(x), gr.top(), int(x), gr.bottom());
            first = true;
            continue;
        }
        double y = gr.bottom() - (s.latency / peak) * gr.height();
        y = qBound(double(gr.top()), y, double(gr.bottom()));
        if (first)
        {
            path.moveTo(x, y);
            first = false;
        }
        else
            path.lineTo(x, y);
    }

    // Fill under
    QPainterPath fill = path;
    if (!m_samples.isEmpty())
    {
        fill.lineTo(gr.right(), gr.bottom());
        fill.lineTo(gr.left(), gr.bottom());
        fill.closeSubpath();
    }
    p.fillPath(fill, QBrush(QColor(29, 110, 245, 25)));
    p.setPen(QPen(QColor("#6366f1"), 2));
    p.drawPath(path);

    // Latest dot
    if (!m_samples.isEmpty() && m_samples.last().ok)
    {
        double x = gr.right();
        double y = gr.bottom() - (m_samples.last().latency / peak) * gr.height();
        y = qBound(double(gr.top()), y, double(gr.bottom()));
        p.setBrush(QColor("#6366f1"));
        p.setPen(Qt::NoPen);
        p.drawEllipse(QPointF(x, y), 4, 4);
    }

    // Time labels
    QFont lf("Segoe UI");
    lf.setPixelSize(9);
    p.setFont(lf);
    p.setPen(QColor("#8a8a8a"));
    p.drawText(QRect(gr.left(), gr.bottom() + 2, 60, 14),
               Qt::AlignLeft, "-2min");
    p.drawText(QRect(gr.right() - 40, gr.bottom() + 2, 40, 14),
               Qt::AlignRight, "now");
}

// ================================================================
// NetworkPerfTab
// ================================================================
NetworkPerfTab::NetworkPerfTab(QWidget *parent) : QWidget(parent)
{
    auto *outer = new QVBoxLayout(this);
    outer->setContentsMargins(0, 0, 0, 0);
    outer->setSpacing(0);

    // Top bar
    auto *topBar = new QWidget(this);
    topBar->setObjectName("TopBar");
    topBar->setFixedHeight(64);
    auto *tl = new QHBoxLayout(topBar);
    tl->setContentsMargins(24, 0, 24, 0);
    auto *ttl = new QLabel("Network Performance", topBar);
    ttl->setStyleSheet("color:#cccccc;font-size:22px;font-weight:600;"
                       "font-family:'Segoe UI','Ubuntu',Arial,sans-serif;");
    m_statusLabel = new QLabel("Pinging 8.8.8.8...", topBar);
    m_statusLabel->setStyleSheet("color:#8a8a8a;font-size:14px;"
                                 "font-family:'Segoe UI','Ubuntu',Arial,sans-serif;");
    tl->addWidget(ttl);
    tl->addSpacing(16);
    tl->addWidget(m_statusLabel);
    tl->addStretch();
    outer->addWidget(topBar);

    auto *div = new QFrame(this);
    div->setFrameShape(QFrame::HLine);
    div->setStyleSheet("background:#3e3e42;max-height:1px;");
    outer->addWidget(div);

    auto *content = new QWidget(this);
    content->setStyleSheet("background:#1e1e1e;");
    auto *cl = new QVBoxLayout(content);
    cl->setContentsMargins(20, 16, 20, 20);
    cl->setSpacing(16);

    // Stat cards
    auto *cardsRow = new QHBoxLayout();
    cardsRow->setSpacing(12);
    auto mkCard = [&](const QString &lbl, QLabel *&val,
                      const QString &col = "#cccccc")
    {
        auto *c = new QWidget(content);
        c->setObjectName("StatCard");
        c->setMinimumWidth(140);
        auto *cv = new QVBoxLayout(c);
        cv->setContentsMargins(16, 12, 16, 12);
        cv->setSpacing(6);
        auto *ll = new QLabel(lbl, c);
        ll->setStyleSheet("color:#8a8a8a;font-size:11px;font-weight:700;"
                          "letter-spacing:1px;background:transparent;");
        val = new QLabel("-", c);
        val->setStyleSheet(
            QString("color:%1;font-size:22px;font-weight:600;"
                    "background:transparent;")
                .arg(col));
        cv->addWidget(ll);
        cv->addWidget(val);
        cardsRow->addWidget(c, 1);
    };
    mkCard("LATENCY", m_latencyCard, "#6366f1");
    mkCard("PACKET LOSS", m_lossCard, "#10b981");
    mkCard("JITTER", m_jitterCard, "#cccccc");
    mkCard("QUALITY", m_qualityCard, "#10b981");
    cl->addLayout(cardsRow);

    // Label
    auto *glbl = new QLabel("LATENCY OVER TIME  (8.8.8.8)", content);
    glbl->setStyleSheet("color:#8a8a8a;font-size:11px;font-weight:700;"
                        "letter-spacing:1.5px;background:transparent;");
    cl->addWidget(glbl);

    m_graph = new LatencyGraph(content);
    cl->addWidget(m_graph, 1);
    cl->addStretch();

    outer->addWidget(content, 1);

    // Ping timer
    m_timer = new QTimer(this);
    m_timer->setInterval(1000);
    connect(m_timer, &QTimer::timeout, this, &NetworkPerfTab::startPing);
    m_timer->start();
}

void NetworkPerfTab::startPing()
{
    if (m_pingProc && m_pingProc->state() != QProcess::NotRunning)
        return;

    if (!m_pingProc)
    {
        m_pingProc = new QProcess(this);
        connect(m_pingProc,
                QOverload<int, QProcess::ExitStatus>::of(&QProcess::finished),
                this, &NetworkPerfTab::onPingResult);
    }

    m_sent++;
    m_pingProc->start("ping", {"-c", "1", "-W", "2", m_target});
}

void NetworkPerfTab::onPingResult(int exitCode, QProcess::ExitStatus)
{
    QString output = m_pingProc->readAllStandardOutput();

    if (exitCode != 0)
    {
        m_graph->addSample(0, false);
    }
    else
    {
        // Parse "time=12.3 ms"
        QRegularExpression re(R"(time=([\d\.]+)\s*ms)");
        auto match = re.match(output);
        if (match.hasMatch())
        {
            double ms = match.captured(1).toDouble();
            m_latencies.append(ms);
            if (m_latencies.size() > 120)
                m_latencies.removeFirst();
            m_recv++;
            m_graph->addSample(ms, true);
        }
        else
        {
            m_graph->addSample(0, false);
        }
    }
    updateCards();
}

void NetworkPerfTab::updateCards()
{
    double avg = m_graph->avgLatency();
    double loss = m_graph->packetLoss();

    // Jitter = std dev of latency
    double jitter = 0;
    if (m_latencies.size() > 1)
    {
        double mean = avg;
        double sq = 0;
        for (double v : m_latencies)
            sq += (v - mean) * (v - mean);
        jitter = qSqrt(sq / m_latencies.size());
    }

    // Quality score
    int quality = 100;
    if (avg > 200)
        quality -= 40;
    else if (avg > 100)
        quality -= 20;
    else if (avg > 50)
        quality -= 10;
    if (loss > 10)
        quality -= 40;
    else if (loss > 5)
        quality -= 20;
    else if (loss > 1)
        quality -= 10;
    if (jitter > 20)
        quality -= 10;
    quality = qBound(0, quality, 100);

    QString qualLabel = quality >= 80 ? "Excellent" : quality >= 60 ? "Good"
                                                  : quality >= 40   ? "Fair"
                                                                    : "Poor";
    QString qualColor = quality >= 80 ? "#10b981" : quality >= 60 ? "#6366f1"
                                                : quality >= 40   ? "#ce9178"
                                                                  : "#ef4444";

    m_latencyCard->setText(avg > 0 ? QString("%1ms").arg(avg, 0, 'f', 1) : "-");
    m_lossCard->setText(QString("%1%").arg(loss, 0, 'f', 1));
    m_jitterCard->setText(jitter > 0 ? QString("%1ms").arg(jitter, 0, 'f', 1) : "-");
    m_qualityCard->setText(qualLabel);
    m_qualityCard->setStyleSheet(
        QString("color:%1;font-size:22px;font-weight:600;"
                "background:transparent;")
            .arg(qualColor));
    m_lossCard->setStyleSheet(
        QString("color:%1;font-size:22px;font-weight:600;"
                "background:transparent;")
            .arg(loss > 5 ? "#ef4444" : loss > 1 ? "#ce9178"
                                                 : "#10b981"));

    m_statusLabel->setText(
        QString("Target: %1  |  Sent: %2  |  Recv: %3")
            .arg(m_target)
            .arg(m_sent)
            .arg(m_recv));
}