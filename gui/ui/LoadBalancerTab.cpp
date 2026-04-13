#include "LoadBalancerTab.h"
#include "Style.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QFrame>
#include <QPainter>
#include <QPainterPath>
#include <QMouseEvent>
#include <QtMath>
#include <algorithm>

// ================================================================
// ProcessLoadBar
// ================================================================
ProcessLoadBar::ProcessLoadBar(QWidget *parent) : QWidget(parent)
{
    setFixedHeight(80);
    setCursor(Qt::PointingHandCursor);
    setMouseTracking(true);
}

void ProcessLoadBar::setData(const QString &process,
                              const QString &exe,
                              quint32 rateOut,
                              quint32 rateIn,
                              quint64 totalBytes,
                              int connections,
                              quint32 peakOut,
                              quint32 peakIn,
                              const QString &anomaly)
{
    m_process    = process;
    m_exe        = exe;
    m_rateOut    = rateOut;
    m_rateIn     = rateIn;
    m_totalBytes = totalBytes;
    m_conns      = connections;
    m_peakOut    = qMax(peakOut, (quint32)1);
    m_peakIn     = qMax(peakIn,  (quint32)1);
    m_anomaly    = anomaly;
    update();
}

QString ProcessLoadBar::fmtRate(quint32 bps) const {
    if (bps == 0)      return "0 B/s";
    if (bps < 1024)    return QString("%1 B/s").arg(bps);
    if (bps < 1048576) return QString("%1 KB/s").arg(bps/1024.0,0,'f',1);
    return             QString("%1 MB/s").arg(bps/1048576.0,0,'f',1);
}

QString ProcessLoadBar::fmtBytes(quint64 b) const {
    if (b < 1024)       return QString("%1 B").arg(b);
    if (b < 1048576)    return QString("%1 KB").arg(b/1024.0,0,'f',1);
    if (b < 1073741824) return QString("%1 MB").arg(b/1048576.0,0,'f',1);
    return              QString("%1 GB").arg(b/1073741824.0,0,'f',2);
}

void ProcessLoadBar::paintEvent(QPaintEvent *)
{
    QPainter p(this);
    p.setRenderHint(QPainter::Antialiasing);
    QRect r = rect();

    bool hasAnomaly = !m_anomaly.isEmpty() &&
                      m_anomaly != "NONE" &&
                      m_anomaly != "None";

    // Background
    p.fillRect(r, hasAnomaly ? QColor("#fef2f2") : QColor("#ffffff"));

    // Left accent bar
    p.fillRect(0, 0, 3, r.height(),
               hasAnomaly ? QColor("#ef4444") : QColor("#6366f1"));

    // Process name
    QFont nf("Ubuntu Mono"); nf.setPixelSize(15); nf.setWeight(QFont::Medium);
    p.setFont(nf);
    p.setPen(hasAnomaly ? QColor("#ef4444") : QColor("#1e2a3a"));
    p.drawText(QRect(14, 8, 220, 22),
               Qt::AlignLeft|Qt::AlignVCenter, m_process);

    // Exe path
    QFont ef("Ubuntu Mono"); ef.setPixelSize(11);
    p.setFont(ef);
    p.setPen(QColor("#9ba8b6"));
    QString exe = m_exe.length() > 45 ? "..." + m_exe.right(42) : m_exe;
    p.drawText(QRect(14, 30, 320, 16),
               Qt::AlignLeft|Qt::AlignVCenter, exe);

    // Anomaly badge
    if (hasAnomaly) {
        QFont bf("Ubuntu Mono"); bf.setPixelSize(10); bf.setWeight(QFont::Bold);
        p.setFont(bf);
        QFontMetrics fm(bf);
        int bw = fm.horizontalAdvance(m_anomaly) + 14;
        QRect badgeR(14, 50, bw, 18);
        p.fillRect(badgeR, QColor("#2d0808"));
        p.setPen(QColor("#ef4444"));
        p.drawRect(badgeR);
        p.drawText(badgeR, Qt::AlignCenter, m_anomaly);
    }

    // Right side stats
    int rx = r.width() - 300;

    // Connection count + total bytes
    QFont sf("Ubuntu Mono"); sf.setPixelSize(12);
    p.setFont(sf);
    p.setPen(QColor("#5c6b7f"));
    p.drawText(QRect(rx, 8, 90, 18),
               Qt::AlignRight|Qt::AlignVCenter,
               QString("%1 conns").arg(m_conns));
    p.drawText(QRect(rx + 100, 8, 100, 18),
               Qt::AlignRight|Qt::AlignVCenter,
               fmtBytes(m_totalBytes));

    // Bars
    int barX = r.width() - 180;
    int barW = 160;
    int barH = 10;
    int outY = 28;
    int inY  = 46;

    // Labels
    QFont lf("Ubuntu Mono"); lf.setPixelSize(10);
    p.setFont(lf);
    p.setPen(QColor("#9ba8b6"));
    p.drawText(QRect(barX-34, outY, 32, barH),
               Qt::AlignRight|Qt::AlignVCenter, "OUT");
    p.drawText(QRect(barX-34, inY, 32, barH),
               Qt::AlignRight|Qt::AlignVCenter, "IN");

    // Bar backgrounds
    p.setPen(Qt::NoPen);
    p.fillRect(barX, outY, barW, barH, QColor("#e4e8ee"));
    p.fillRect(barX, inY,  barW, barH, QColor("#e4e8ee"));

    // Filled bars
    double outRatio = qMin(1.0, m_rateOut / double(m_peakOut));
    double inRatio  = qMin(1.0, m_rateIn  / double(m_peakIn));

    if (outRatio > 0) {
        QLinearGradient og(barX,0,barX+barW,0);
        og.setColorAt(0,"#6366f1"); og.setColorAt(1,"#6366f1");
        p.fillRect(barX, outY, int(barW*outRatio), barH, og);
    }
    if (inRatio > 0) {
        QLinearGradient ig(barX,0,barX+barW,0);
        ig.setColorAt(0,"#10b981"); ig.setColorAt(1,"#6ee7a0");
        p.fillRect(barX, inY, int(barW*inRatio), barH, ig);
    }

    // Rate values
    p.setFont(lf);
    p.setPen(m_rateOut>0 ? QColor("#6366f1") : QColor("#9ba8b6"));
    p.drawText(QRect(barX, outY+12, barW, 14),
               Qt::AlignLeft|Qt::AlignVCenter, fmtRate(m_rateOut));
    p.setPen(m_rateIn>0 ? QColor("#10b981") : QColor("#9ba8b6"));
    p.drawText(QRect(barX, inY+12, barW, 14),
               Qt::AlignLeft|Qt::AlignVCenter, fmtRate(m_rateIn));

    // Divider
    p.setPen(QPen(QColor("#e4e8ee"),1));
    p.drawLine(0, r.height()-1, r.width(), r.height()-1);
}

void ProcessLoadBar::mousePressEvent(QMouseEvent *)
{
    emit clicked(m_process);
}

// ================================================================
// LoadBalancerTab
// ================================================================
LoadBalancerTab::LoadBalancerTab(QWidget *parent) : QWidget(parent)
{
    auto *outer = new QVBoxLayout(this);
    outer->setContentsMargins(0,0,0,0);
    outer->setSpacing(0);

    // Top bar
    auto *topBar = new QWidget(this);
    topBar->setObjectName("TopBar");
    topBar->setFixedHeight(58);
    auto *tl = new QHBoxLayout(topBar);
    tl->setContentsMargins(20,0,20,0);

    auto *title = new QLabel("Bandwidth Load", topBar);
    title->setStyleSheet("color:#1e2a3a;font-size:15px;font-weight:600;"
                         "font-family:'Ubuntu Mono';");
    auto *hint = new QLabel(
        "Live bandwidth per process  —  click any row to inspect",
        topBar);
    hint->setStyleSheet("color:#9ba8b6;font-size:12px;"
                        "font-family:'Ubuntu Mono';");
    m_totalLabel = new QLabel("", topBar);
    m_totalLabel->setStyleSheet("color:#5c6b7f;font-size:12px;"
                                "font-family:'Ubuntu Mono';");
    tl->addWidget(title);
    tl->addSpacing(16);
    tl->addWidget(hint);
    tl->addStretch();
    tl->addWidget(m_totalLabel);
    outer->addWidget(topBar);

    // Column headers
    auto *hdr = new QWidget(this);
    hdr->setFixedHeight(30);
    hdr->setStyleSheet("background:#f7f8fa;");
    auto *hl = new QHBoxLayout(hdr);
    hl->setContentsMargins(17,0,20,0);
    auto mkH = [&](const QString &t, int stretch=0) {
        auto *l = new QLabel(t, hdr);
        l->setStyleSheet("color:#9ba8b6;font-size:10px;font-weight:700;"
                         "font-family:'Ubuntu Mono';letter-spacing:1px;");
        if (stretch) hl->addWidget(l,stretch);
        else hl->addWidget(l);
    };
    mkH("PROCESS / EXECUTABLE", 1);
    mkH("CONNS"); hl->addSpacing(20);
    mkH("TOTAL"); hl->addSpacing(60);
    mkH("OUT BANDWIDTH"); hl->addSpacing(20);
    mkH("IN BANDWIDTH");
    outer->addWidget(hdr);

    auto *div = new QFrame(this);
    div->setFrameShape(QFrame::HLine);
    div->setStyleSheet("background:#e4e8ee;max-height:1px;");
    outer->addWidget(div);

    // Scroll area
    m_scroll = new QScrollArea(this);
    m_scroll->setWidgetResizable(true);
    m_scroll->setFrameShape(QFrame::NoFrame);
    m_scroll->setStyleSheet("QScrollArea{background:#ffffff;border:none;}");

    m_container = new QWidget(m_scroll);
    m_container->setStyleSheet("background:#ffffff;");
    auto *cl = new QVBoxLayout(m_container);
    cl->setContentsMargins(0,0,0,0);
    cl->setSpacing(0);
    cl->addStretch();
    m_scroll->setWidget(m_container);
    outer->addWidget(m_scroll, 1);
}

void LoadBalancerTab::updateData(const QVector<ProcEntry> &procs,
                                  const QVector<TrafficEntry> &conns)
{
    m_procs = procs;
    m_conns = conns;

    for (const auto &p : procs) {
        m_peakOut[p.process] = qMax(m_peakOut.value(p.process,0), p.rateOutBps);
        m_peakIn[p.process]  = qMax(m_peakIn.value(p.process,0),  p.rateInBps);
    }
    rebuild();
}

void LoadBalancerTab::rebuild()
{
    // Sort by bandwidth
    QVector<ProcEntry> sorted = m_procs;
    std::sort(sorted.begin(), sorted.end(),
        [](const ProcEntry &a, const ProcEntry &b) {
            return (a.rateOutBps+a.rateInBps) > (b.rateOutBps+b.rateInBps);
        });

    // Clear old bars (keep stretch at end)
    auto *lay = static_cast<QVBoxLayout*>(m_container->layout());
    while (lay->count() > 1) {
        auto *item = lay->takeAt(0);
        if (item->widget()) item->widget()->deleteLater();
        delete item;
    }

    // Total
    quint64 tOut=0, tIn=0;
    for (const auto &p : sorted) { tOut+=p.rateOutBps; tIn+=p.rateInBps; }
    auto fmtR=[](quint64 b)->QString{
        if(b<1024) return QString("%1 B/s").arg(b);
        if(b<1048576) return QString("%1 KB/s").arg(b/1024.0,0,'f',1);
        return QString("%1 MB/s").arg(b/1048576.0,0,'f',1);
    };
    m_totalLabel->setText(
        QString("Total  OUT %1  IN %2").arg(fmtR(tOut),fmtR(tIn)));

    // Connection count per process
    QMap<QString,int> connCount;
    for (const auto &e : m_conns)
        if (e.isActive()) connCount[e.process]++;

    int pos = 0;
    for (const auto &proc : sorted) {
        auto *bar = new ProcessLoadBar(m_container);
        bar->setData(
            proc.process,
            proc.exe,
            proc.rateOutBps,
            proc.rateInBps,
            proc.bytesOut + proc.bytesIn,
            connCount.value(proc.process, 0),
            m_peakOut.value(proc.process, 1),
            m_peakIn.value(proc.process, 1),
            proc.anomalyStr);   // ← use anomalyStr not anomaly

        connect(bar, &ProcessLoadBar::clicked,
                this, &LoadBalancerTab::processSelected);
        lay->insertWidget(pos++, bar);
    }
}
