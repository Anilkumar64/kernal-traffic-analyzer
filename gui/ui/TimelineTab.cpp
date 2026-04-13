#include "TimelineTab.h"
#include "Style.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QFrame>
#include <QPainter>
#include <QPainterPath>
#include <QScrollBar>
#include <QMouseEvent>
#include <QToolTip>
#include <QDateTime>

// ================================================================
// TimelineCanvas
// ================================================================
TimelineCanvas::TimelineCanvas(QWidget *parent) : QWidget(parent)
{
    setMouseTracking(true);
    setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred);
}

void TimelineCanvas::setEntries(const QVector<TimelineEntry> &entries,
                                const QString &filter)
{
    QVector<TimelineEntry> filtered;
    for (const auto &e : entries)
    {
        if (filter == "TCP" && e.protocol != "TCP")
            continue;
        if (filter == "UDP" && e.protocol != "UDP")
            continue;
        if (filter == "Active" && !e.isActive)
            continue;
        filtered.append(e);
    }
    m_entries = filtered;
    setMinimumHeight(qMax(200, m_entries.size() * ROW_H + 40));
    update();
}

void TimelineCanvas::paintEvent(QPaintEvent *)
{
    QPainter p(this);
    p.setRenderHint(QPainter::Antialiasing);
    QRect r = rect();
    p.fillRect(r, QColor("#252526"));

    qint64 now = QDateTime::currentSecsSinceEpoch();
    qint64 tMin = now - WINDOW_SECS;
    int graphW = r.width() - LABEL_W - 8;

    // Time axis
    QFont tf("Ubuntu Mono");
    tf.setPixelSize(9);
    p.setFont(tf);
    p.setPen(QPen(QColor("#3e3e42"), 1, Qt::DotLine));
    for (int i = 0; i <= 6; ++i)
    {
        qint64 ts = tMin + i * (WINDOW_SECS / 6);
        int x = LABEL_W + int(double(ts - tMin) / WINDOW_SECS * graphW);
        p.drawLine(x, 0, x, r.height());
        p.setPen(QColor("#8a8a8a"));
        p.drawText(QRect(x - 25, r.height() - 16, 50, 14),
                   Qt::AlignCenter,
                   QDateTime::fromSecsSinceEpoch(ts).toString("hh:mm"));
        p.setPen(QPen(QColor("#3e3e42"), 1, Qt::DotLine));
    }

    if (m_entries.isEmpty())
    {
        QFont nf("Ubuntu Mono");
        nf.setPixelSize(13);
        p.setFont(nf);
        p.setPen(QColor("#555555"));
        p.drawText(r.adjusted(LABEL_W, 0, 0, 0),
                   Qt::AlignCenter, "No connections in the last 30 minutes");
        return;
    }

    QFont lf("Ubuntu Mono");
    lf.setPixelSize(12);
    p.setFont(lf);

    for (int i = 0; i < m_entries.size(); ++i)
    {
        const TimelineEntry &e = m_entries[i];
        int y = i * ROW_H;
        QRect rowR(0, y, r.width(), ROW_H);

        // Row background
        QColor rowBg = (i == m_hoverRow) ? QColor("#3e3e42") : (i % 2 == 0) ? QColor("#252526")
                                                                            : QColor("#0d1219");
        p.fillRect(rowR, rowBg);

        // Label
        QString label = e.process;
        if (!e.domain.isEmpty() && e.domain != "-")
            label += " → " + e.domain;
        else
            label += " → " + e.destIp;
        if (label.length() > 28)
            label = label.left(25) + "...";

        p.setPen(e.isActive ? QColor("#cccccc") : QColor("#8a8a8a"));
        p.drawText(QRect(8, y + 4, LABEL_W - 12, ROW_H - 8),
                   Qt::AlignLeft | Qt::AlignVCenter, label);

        // Bar
        qint64 start = qMax(e.firstSeen, tMin);
        qint64 end = e.isActive ? now : qMin(e.lastSeen, now);
        if (end <= start)
            continue;

        double x1 = LABEL_W + double(start - tMin) / WINDOW_SECS * graphW;
        double x2 = LABEL_W + double(end - tMin) / WINDOW_SECS * graphW;
        double bh = ROW_H - 10;
        QRectF barR(x1, y + 5, qMax(2.0, x2 - x1), bh);

        QColor barColor = e.protocol == "TCP" ? QColor("#6366f1") : QColor("#3794ff");
        if (!e.isActive)
            barColor.setAlpha(80);

        p.setPen(Qt::NoPen);
        p.setBrush(barColor);
        p.drawRoundedRect(barR, 3, 3);

        // Pulsing right edge for active
        if (e.isActive)
        {
            p.setBrush(QColor("#3794ff"));
            p.drawEllipse(QPointF(x2, y + ROW_H / 2.0), 3.0, 3.0);
        }

        // Protocol label inside bar
        if (barR.width() > 40)
        {
            QFont bf("Ubuntu Mono");
            bf.setPixelSize(9);
            p.setFont(bf);
            p.setPen(Qt::white);
            p.drawText(barR.adjusted(4, 0, -4, 0),
                       Qt::AlignLeft | Qt::AlignVCenter,
                       e.protocol);
        }
    }
    p.setFont(lf);
}

void TimelineCanvas::mousePressEvent(QMouseEvent *e)
{
    int row = e->position().y() / ROW_H;
    if (row >= 0 && row < m_entries.size())
    {
        const TimelineEntry &te = m_entries[row];
        qint64 dur = te.lastSeen - te.firstSeen;
        QString info = QString(
                           "Process: %1\nDomain: %2\nProtocol: %3\nState: %4\n"
                           "Duration: %5s\nBytes: %6")
                           .arg(te.process)
                           .arg(te.domain.isEmpty() ? te.destIp : te.domain)
                           .arg(te.protocol)
                           .arg(te.state)
                           .arg(dur)
                           .arg(te.bytes);
        QToolTip::showText(e->globalPosition().toPoint(), info);
    }
}

void TimelineCanvas::mouseMoveEvent(QMouseEvent *e)
{
    int row = e->position().y() / ROW_H;
    if (row != m_hoverRow)
    {
        m_hoverRow = row;
        update();
    }
}

// ================================================================
// TimelineTab
// ================================================================
TimelineTab::TimelineTab(QWidget *parent) : QWidget(parent)
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
    tl->setSpacing(12);

    auto *ttl = new QLabel("Connection Timeline", topBar);
    ttl->setStyleSheet("color:#cccccc;font-size:17px;font-weight:600;"
                       "font-family:'Ubuntu Mono';");
    m_countLabel = new QLabel("", topBar);
    m_countLabel->setStyleSheet("color:#8a8a8a;font-size:14px;"
                                "font-family:'Ubuntu Mono';");
    m_filter = new QComboBox(topBar);
    m_filter->addItems({"All", "TCP", "UDP", "Active"});
    m_filter->setFixedWidth(100);
    connect(m_filter, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, &TimelineTab::rebuild);

    tl->addWidget(ttl);
    tl->addWidget(m_countLabel);
    tl->addStretch();
    tl->addWidget(new QLabel("Show:", topBar));
    tl->addWidget(m_filter);
    outer->addWidget(topBar);

    auto *div = new QFrame(this);
    div->setFrameShape(QFrame::HLine);
    div->setStyleSheet("background:#3e3e42;max-height:1px;");
    outer->addWidget(div);

    // Legend
    auto *leg = new QWidget(this);
    leg->setFixedHeight(30);
    leg->setStyleSheet("background:#252526;");
    auto *ll = new QHBoxLayout(leg);
    ll->setContentsMargins(12, 0, 12, 0);
    ll->setSpacing(16);
    auto mkDot = [&](const QString &color, const QString &label)
    {
        auto *d = new QLabel(leg);
        d->setFixedSize(10, 10);
        d->setStyleSheet(QString("background:%1;border-radius:5px;").arg(color));
        auto *t = new QLabel(label, leg);
        t->setStyleSheet("color:#8a8a8a;font-size:13px;font-family:'Ubuntu Mono';");
        ll->addWidget(d);
        ll->addWidget(t);
    };
    mkDot("#6366f1", "TCP");
    mkDot("#3794ff", "UDP");
    mkDot("#cccccc", "Active edge");
    ll->addStretch();
    auto *winLabel = new QLabel("← 30 min window →", leg);
    winLabel->setStyleSheet("color:#8a8a8a;font-size:13px;font-family:'Ubuntu Mono';");
    ll->addWidget(winLabel);
    outer->addWidget(leg);

    auto *div2 = new QFrame(this);
    div2->setFrameShape(QFrame::HLine);
    div2->setStyleSheet("background:#3e3e42;max-height:1px;");
    outer->addWidget(div2);

    // Scroll area
    m_scroll = new QScrollArea(this);
    m_scroll->setWidgetResizable(true);
    m_scroll->setFrameShape(QFrame::NoFrame);
    m_scroll->setStyleSheet("background:#1e1e1e;border:none;");

    m_canvas = new TimelineCanvas(m_scroll);
    m_scroll->setWidget(m_canvas);
    outer->addWidget(m_scroll, 1);

    // Pulse timer for animation
    m_pulseTimer = new QTimer(this);
    m_pulseTimer->setInterval(500);
    connect(m_pulseTimer, &QTimer::timeout,
            m_canvas, QOverload<>::of(&QWidget::update));
    m_pulseTimer->start();
}

void TimelineTab::updateData(const QVector<TrafficEntry> &entries)
{
    qint64 cutoff = QDateTime::currentSecsSinceEpoch() - 1800;

    for (const auto &e : entries)
    {
        QString key = QString("%1:%2-%3:%4")
                          .arg(e.srcIp)
                          .arg(e.srcPort)
                          .arg(e.destIp)
                          .arg(e.destPort);

        TimelineEntry te;
        te.process = e.process;
        te.domain = (e.domain.isEmpty() || e.domain == "-") ? "" : e.domain;
        te.destIp = e.destIp;
        te.destPort = e.destPort;
        te.protocol = e.protocol;
        te.state = e.stateString();
        te.firstSeen = e.firstSeen;
        te.lastSeen = e.lastSeen;
        te.isActive = e.isActive();
        te.bytes = e.bytesOut + e.bytesIn;
        m_history[key] = te;
    }

    // Prune old
    for (auto it = m_history.begin(); it != m_history.end();)
    {
        if (!it->isActive && it->lastSeen < cutoff)
            it = m_history.erase(it);
        else
            ++it;
    }

    m_countLabel->setText(
        QString("  %1 connections").arg(m_history.size()));
    rebuild();
}

void TimelineTab::rebuild()
{
    QString filter = m_filter->currentText();
    QVector<TimelineEntry> all;
    all.reserve(m_history.size());
    for (auto it = m_history.begin(); it != m_history.end(); ++it)
        all.append(it.value());

    // Sort: active first, then by firstSeen descending
    std::sort(all.begin(), all.end(),
              [](const TimelineEntry &a, const TimelineEntry &b)
              {
                  if (a.isActive != b.isActive)
                      return a.isActive > b.isActive;
                  return a.firstSeen > b.firstSeen;
              });

    m_canvas->setEntries(all, filter);

    // Auto-scroll to bottom of scroll area to show latest
    QTimer::singleShot(0, [this]()
                       { m_scroll->verticalScrollBar()->setValue(0); });
}
