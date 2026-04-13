#include "HistoryTab.h"
#include "Style.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QFrame>
#include <QSplitter>
#include <QPainter>
#include <QPainterPath>
#include <QDateTime>

// ================================================================
// BwGraph
// ================================================================
BwGraph::BwGraph(const QString &title, Mode mode, QWidget *parent)
    : QWidget(parent), m_title(title), m_mode(mode)
{
    setMinimumHeight(150);
}

void BwGraph::setProcess(const QString &process)
{
    m_process = process;
    refresh();
}

void BwGraph::refresh()
{
    if (m_process.isEmpty()) return;
    if (m_mode == Hour)   m_samples = HistoryDB::instance().getLastHour(m_process);
    if (m_mode == Day24)  m_samples = HistoryDB::instance().getLast24h(m_process);
    if (m_mode == Week)   m_totals  = HistoryDB::instance().getDailyTotals(m_process,7);
    update();
}

QString BwGraph::formatRate(quint32 bps) const {
    if (bps < 1024)    return QString("%1B/s").arg(bps);
    if (bps < 1048576) return QString("%1K").arg(bps/1024.0,0,'f',0);
    return             QString("%1M").arg(bps/1048576.0,0,'f',1);
}

QString BwGraph::formatBytes(quint64 b) const {
    if (b < 1024)       return QString("%1B").arg(b);
    if (b < 1048576)    return QString("%1KB").arg(b/1024.0,0,'f',0);
    if (b < 1073741824) return QString("%1MB").arg(b/1048576.0,0,'f',1);
    return              QString("%1GB").arg(b/1073741824.0,0,'f',2);
}

void BwGraph::paintEvent(QPaintEvent *)
{
    QPainter p(this);
    p.setRenderHint(QPainter::Antialiasing);
    QRect r = rect();

    p.fillRect(r, QColor("#252526"));

    // Title
    QFont tf("Ubuntu Mono"); tf.setPixelSize(11); tf.setWeight(QFont::Bold);
    p.setFont(tf);
    p.setPen(QColor("#8a8a8a"));
    p.drawText(QRect(r.left()+8, r.top()+4, 300, 16),
               Qt::AlignLeft, m_title.toUpper());

    // No data
    bool hasData = (m_mode == Week) ?
        !m_totals.isEmpty() : !m_samples.isEmpty();
    if (!hasData || m_process.isEmpty()) {
        QFont nf("Ubuntu Mono"); nf.setPixelSize(13);
        p.setFont(nf);
        p.setPen(QColor("#3e3e42"));
        p.drawText(r, Qt::AlignCenter,
                   "No history yet — data collects over time");
        return;
    }

    QRect graphR(r.left()+50, r.top()+24,
                 r.width()-60, r.height()-36);

    if (m_mode == Week) {
        drawBarChart(p, graphR, m_totals);
    } else {
        // Build axis labels
        QVector<QString> labels;
        if (m_mode == Hour) {
            for (const auto &s : m_samples)
                labels << QDateTime::fromSecsSinceEpoch(s.ts)
                              .toString("hh:mm");
        } else {
            for (const auto &s : m_samples)
                labels << QDateTime::fromSecsSinceEpoch(s.ts)
                              .toString("HH:00");
        }
        drawGraph(p, graphR, m_samples, labels);
    }
}

void BwGraph::drawGraph(QPainter &p, const QRect &r,
                         const QVector<BwSample> &samples,
                         const QVector<QString> &labels)
{
    if (samples.isEmpty()) return;

    // Find peak
    quint32 peak = 1;
    for (const auto &s : samples)
        peak = qMax(peak, qMax(s.outBps, s.inBps));

    // Grid
    p.setPen(QPen(QColor("#3e3e42"), 1, Qt::DotLine));
    for (int i = 1; i < 4; ++i) {
        int y = r.top() + r.height() * i / 4;
        p.drawLine(r.left(), y, r.right(), y);
        p.setPen(QColor("#8a8a8a"));
        QFont af("Ubuntu Mono"); af.setPixelSize(9);
        p.setFont(af);
        p.drawText(QRect(r.left()-48, y-8, 44, 16),
                   Qt::AlignRight|Qt::AlignVCenter,
                   formatRate(peak * (4-i) / 4));
        p.setPen(QPen(QColor("#3e3e42"), 1, Qt::DotLine));
    }

    double xStep = (samples.size() > 1) ?
        double(r.width()) / (samples.size()-1) : r.width();

    auto drawLine = [&](bool isOut, const QColor &color) {
        QPainterPath path;
        bool first = true;
        for (int i = 0; i < samples.size(); ++i) {
            double x = r.left() + i * xStep;
            quint32 val = isOut ? samples[i].outBps : samples[i].inBps;
            double y = r.bottom() - (val / double(peak)) * r.height();
            y = qBound(double(r.top()), y, double(r.bottom()));
            if (first) { path.moveTo(x, y); first = false; }
            else path.lineTo(x, y);
        }
        QPainterPath fill = path;
        fill.lineTo(r.right(), r.bottom());
        fill.lineTo(r.left(), r.bottom());
        fill.closeSubpath();
        QColor fc = color; fc.setAlpha(20);
        p.fillPath(fill, fc);
        p.setPen(QPen(color, 1.5));
        p.drawPath(path);
    };

    drawLine(true,  QColor("#6366f1"));
    drawLine(false, QColor("#10b981"));

    // X axis labels (every N samples)
    int step = qMax(1, samples.size() / 8);
    QFont lf("Ubuntu Mono"); lf.setPixelSize(9);
    p.setFont(lf);
    p.setPen(QColor("#8a8a8a"));
    for (int i = 0; i < labels.size(); i += step) {
        double x = r.left() + i * xStep;
        p.drawText(QRectF(x-20, r.bottom()+2, 40, 12),
                   Qt::AlignCenter, labels[i]);
    }

    // Legend
    QFont legf("Ubuntu Mono"); legf.setPixelSize(10);
    p.setFont(legf);
    p.setPen(QColor("#6366f1"));
    p.drawText(QRect(r.right()-120, r.top()-20, 50, 14),
               Qt::AlignRight, "OUT");
    p.setPen(QColor("#10b981"));
    p.drawText(QRect(r.right()-60, r.top()-20, 50, 14),
               Qt::AlignRight, "IN");
}

void BwGraph::drawBarChart(QPainter &p, const QRect &r,
                            const QVector<DailyTotal> &totals)
{
    if (totals.isEmpty()) return;
    quint64 peak = 1;
    for (const auto &d : totals)
        peak = qMax(peak, d.totalOut + d.totalIn);

    int n = totals.size();
    double barW = double(r.width()) / n * 0.7;
    double gap  = double(r.width()) / n;

    // Grid
    p.setPen(QPen(QColor("#3e3e42"), 1, Qt::DotLine));
    for (int i = 1; i < 4; ++i) {
        int y = r.top() + r.height() * i / 4;
        p.drawLine(r.left(), y, r.right(), y);
    }

    QFont lf("Ubuntu Mono"); lf.setPixelSize(9);
    p.setFont(lf);

    for (int i = 0; i < n; ++i) {
        double x = r.left() + i * gap + (gap - barW) / 2.0;
        quint64 total = totals[i].totalOut + totals[i].totalIn;
        double h = (total / double(peak)) * r.height();
        double outH = (totals[i].totalOut / double(peak)) * r.height();

        QRectF outR(x, r.bottom() - outH, barW, outH);
        QRectF inR (x, r.bottom() - h,    barW, h - outH);

        p.fillRect(outR, QColor("#6366f1"));
        p.fillRect(inR,  QColor("#10b981"));

        // Date label
        QString date = totals[i].date.right(5); // MM-DD
        p.setPen(QColor("#8a8a8a"));
        p.drawText(QRectF(x, r.bottom()+2, barW, 12),
                   Qt::AlignCenter, date);
    }
}

// ================================================================
// HistoryTab
// ================================================================
HistoryTab::HistoryTab(QWidget *parent) : QWidget(parent)
{
    auto *outer = new QVBoxLayout(this);
    outer->setContentsMargins(0,0,0,0);
    outer->setSpacing(0);

    // Top bar
    auto *topBar = new QWidget(this);
    topBar->setObjectName("TopBar");
    topBar->setFixedHeight(64);
    auto *tl = new QHBoxLayout(topBar);
    tl->setContentsMargins(20,0,20,0);
    auto *ttl = new QLabel("Traffic History", topBar);
    ttl->setStyleSheet("color:#cccccc;font-size:17px;font-weight:600;"
                       "font-family:'Ubuntu Mono';");
    auto *sub = new QLabel("Historical bandwidth per process", topBar);
    sub->setStyleSheet("color:#8a8a8a;font-size:13px;font-family:'Ubuntu Mono';");
    tl->addWidget(ttl); tl->addSpacing(16); tl->addWidget(sub); tl->addStretch();
    outer->addWidget(topBar);

    auto *div = new QFrame(this);
    div->setFrameShape(QFrame::HLine);
    div->setStyleSheet("background:#3e3e42;max-height:1px;");
    outer->addWidget(div);

    // Splitter
    auto *split = new QSplitter(Qt::Horizontal, this);
    split->setHandleWidth(1);

    // Process list
    auto *left = new QWidget(split);
    left->setFixedWidth(180);
    left->setStyleSheet("background:#252526;");
    auto *ll = new QVBoxLayout(left);
    ll->setContentsMargins(0,0,0,0);
    auto *lhdr = new QLabel("  PROCESSES", left);
    lhdr->setObjectName("SectionTitle");
    lhdr->setFixedHeight(40);
    ll->addWidget(lhdr);
    auto *ldiv = new QFrame(left);
    ldiv->setFrameShape(QFrame::HLine);
    ldiv->setStyleSheet("background:#3e3e42;max-height:1px;");
    ll->addWidget(ldiv);
    m_procList = new QListWidget(left);
    m_procList->setStyleSheet(
        "QListWidget{background:#1e1e1e;border:none;"
        "font-family:'Ubuntu Mono';font-size:13px;}"
        "QListWidget::item{padding:8px 14px;border-bottom:1px solid #252526;}"
        "QListWidget::item:selected{background:#252545;color:#c586c0;"
        "border-left:2px solid #6366f1;}"
        "QListWidget::item:hover{background:#3e3e42;}");
    connect(m_procList, &QListWidget::itemClicked,
            this, &HistoryTab::onProcessSelected);
    ll->addWidget(m_procList, 1);

    // Graphs
    auto *right = new QWidget(split);
    auto *rl = new QVBoxLayout(right);
    rl->setContentsMargins(0,0,0,0);
    rl->setSpacing(1);
    right->setStyleSheet("background:#1e1e1e;");

    m_hourGraph = new BwGraph("Last 1 Hour",  BwGraph::Hour,  right);
    m_dayGraph  = new BwGraph("Last 24 Hours",BwGraph::Day24, right);
    m_weekGraph = new BwGraph("7-Day Totals", BwGraph::Week,  right);

    rl->addWidget(m_hourGraph, 1);
    auto *d1 = new QFrame(right);
    d1->setFrameShape(QFrame::HLine);
    d1->setStyleSheet("background:#3e3e42;max-height:1px;");
    rl->addWidget(d1);
    rl->addWidget(m_dayGraph, 1);
    auto *d2 = new QFrame(right);
    d2->setFrameShape(QFrame::HLine);
    d2->setStyleSheet("background:#3e3e42;max-height:1px;");
    rl->addWidget(d2);
    rl->addWidget(m_weekGraph, 1);

    split->addWidget(left);
    split->addWidget(right);
    split->setStretchFactor(0,0);
    split->setStretchFactor(1,1);
    outer->addWidget(split, 1);

    m_refreshTimer = new QTimer(this);
    m_refreshTimer->setInterval(60000);
    connect(m_refreshTimer, &QTimer::timeout, this, &HistoryTab::refresh);
    m_refreshTimer->start();

    rebuildProcessList();
}

void HistoryTab::rebuildProcessList()
{
    QString cur = m_selectedProcess;
    m_procList->blockSignals(true);
    m_procList->clear();
    QStringList procs = HistoryDB::instance().getProcessList();
    for (const QString &p : procs) {
        auto *item = new QListWidgetItem(p, m_procList);
        if (p == cur) m_procList->setCurrentItem(item);
    }
    m_procList->blockSignals(false);
    if (!cur.isEmpty()) {
        m_hourGraph->setProcess(cur);
        m_dayGraph->setProcess(cur);
        m_weekGraph->setProcess(cur);
    }
}

void HistoryTab::refresh()
{
    rebuildProcessList();
    m_hourGraph->refresh();
    m_dayGraph->refresh();
    m_weekGraph->refresh();
}

void HistoryTab::onProcessSelected(QListWidgetItem *item)
{
    m_selectedProcess = item->text();
    m_hourGraph->setProcess(m_selectedProcess);
    m_dayGraph->setProcess(m_selectedProcess);
    m_weekGraph->setProcess(m_selectedProcess);
}
