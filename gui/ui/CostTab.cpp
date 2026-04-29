#include "CostTab.h"
#include "Style.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QGridLayout>
#include <QFrame>
#include <QHeaderView>
#include <QPushButton>
#include <QPainter>
#include <QMouseEvent>
#include <QToolTip>
#include <QScrollArea>

// ================================================================
// CostBarChart
// ================================================================
CostBarChart::CostBarChart(QWidget *parent) : QWidget(parent)
{
    setFixedHeight(140);
    setMouseTracking(true);
}

void CostBarChart::setData(const QVector<DailyTotal> &totals,
                            double rateInrPerGb)
{
    m_totals = totals;
    m_rate   = rateInrPerGb;
    update();
}

void CostBarChart::mouseMoveEvent(QMouseEvent *e)
{
    if (m_totals.isEmpty()) return;
    QRect r = rect().adjusted(50, 10, -10, -20);
    double barW = double(r.width()) / m_totals.size() * 0.7;
    double gap  = double(r.width()) / m_totals.size();

    for (int i = 0; i < m_totals.size(); ++i) {
        double x = r.left() + i * gap;
        if (e->position().x() >= x && e->position().x() <= x + gap) {
            quint64 bytes = m_totals[i].totalOut + m_totals[i].totalIn;
            double  cost  = bytes / (1024.0*1024.0*1024.0) * m_rate;
            QToolTip::showText(e->globalPosition().toPoint(),
                QString("%1\n₹%2\n%3 MB")
                    .arg(m_totals[i].date)
                    .arg(cost, 0, 'f', 2)
                    .arg(bytes/1048576.0, 0, 'f', 1));
            m_hoverIdx = i;
            update();
            return;
        }
    }
    m_hoverIdx = -1;
    update();
}

void CostBarChart::paintEvent(QPaintEvent *)
{
    QPainter p(this);
    p.setRenderHint(QPainter::Antialiasing);
    QRect r = rect().adjusted(50, 10, -10, -20);
    p.fillRect(rect(), QColor("#252526"));

    if (m_totals.isEmpty()) {
        QFont f("Segoe UI"); f.setPixelSize(12);
        p.setFont(f);
        p.setPen(QColor("#555555"));
        p.drawText(rect(), Qt::AlignCenter, "No cost data yet");
        return;
    }

    double peak = 0;
    for (const auto &d : m_totals) {
        quint64 bytes = d.totalOut + d.totalIn;
        double cost = bytes / (1024.0*1024.0*1024.0) * m_rate;
        peak = qMax(peak, cost);
    }
    if (peak <= 0) peak = 1;

    // Grid
    p.setPen(QPen(QColor("#333333"), 1, Qt::DotLine));
    for (int i = 1; i < 4; ++i) {
        int y = r.top() + r.height() * i / 4;
        p.drawLine(r.left(), y, r.right(), y);
        QFont af("Segoe UI"); af.setPixelSize(9);
        p.setFont(af);
        p.setPen(QColor("#8a8a8a"));
        p.drawText(QRect(r.left()-48, y-8, 44, 16),
                   Qt::AlignRight|Qt::AlignVCenter,
                   QString("₹%1").arg(peak*(4-i)/4, 0,'f',1));
        p.setPen(QPen(QColor("#333333"), 1, Qt::DotLine));
    }

    int n = m_totals.size();
    double barW = double(r.width()) / n * 0.65;
    double gap  = double(r.width()) / n;

    QFont lf("Segoe UI"); lf.setPixelSize(9);
    p.setFont(lf);

    for (int i = 0; i < n; ++i) {
        double x = r.left() + i * gap + (gap - barW) / 2.0;
        quint64 bytes = m_totals[i].totalOut + m_totals[i].totalIn;
        double cost = bytes / (1024.0*1024.0*1024.0) * m_rate;
        double h = (cost / peak) * r.height();

        QColor barColor = (i == m_hoverIdx) ?
            QColor("#ce9178") : QColor("#6366f1");
        p.fillRect(QRectF(x, r.bottom()-h, barW, h), barColor);

        p.setPen(QColor("#8a8a8a"));
        QString date = m_totals[i].date.right(5);
        p.drawText(QRectF(x, r.bottom()+2, barW, 12), Qt::AlignCenter, date);
    }
}

// ================================================================
// CostTab
// ================================================================
CostTab::CostTab(QWidget *parent) : QWidget(parent)
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
    tl->setSpacing(12);

    auto *ttl = new QLabel("Data Cost", topBar);
    ttl->setStyleSheet("color:#ffffff;font-size:17px;font-weight:600;"
                       "font-family:'Segoe UI','Ubuntu',Arial,sans-serif;");

    // Settings
    auto *rateLabel = new QLabel("Rate: ₹", topBar);
    rateLabel->setStyleSheet("color:#8a8a8a;font-size:13px;font-family:'Segoe UI','Ubuntu',Arial,sans-serif;");
    m_rateSpinBox = new QDoubleSpinBox(topBar);
    m_rateSpinBox->setRange(0.1, 10000.0);
    m_rateSpinBox->setDecimals(2);
    m_rateSpinBox->setValue(CostTracker::instance().rateInrPerGb());
    m_rateSpinBox->setFixedWidth(90);

    auto *perGb = new QLabel("/GB    Limit:", topBar);
    perGb->setStyleSheet("color:#8a8a8a;font-size:13px;font-family:'Segoe UI','Ubuntu',Arial,sans-serif;");
    m_limitSpinBox = new QDoubleSpinBox(topBar);
    m_limitSpinBox->setRange(1.0, 10000.0);
    m_limitSpinBox->setDecimals(0);
    m_limitSpinBox->setValue(CostTracker::instance().limitGb());
    m_limitSpinBox->setFixedWidth(80);

    auto *gbLabel = new QLabel("GB", topBar);
    gbLabel->setStyleSheet("color:#8a8a8a;font-size:13px;font-family:'Segoe UI','Ubuntu',Arial,sans-serif;");

    auto *saveBtn = new QPushButton("Save", topBar);
    saveBtn->setFixedWidth(70);
    connect(saveBtn, &QPushButton::clicked, this, &CostTab::onSave);

    tl->addWidget(ttl); tl->addStretch();
    tl->addWidget(rateLabel); tl->addWidget(m_rateSpinBox);
    tl->addWidget(perGb); tl->addWidget(m_limitSpinBox);
    tl->addWidget(gbLabel); tl->addSpacing(8); tl->addWidget(saveBtn);
    outer->addWidget(topBar);

    auto *hline = new QFrame(this);
    hline->setFrameShape(QFrame::HLine);
    hline->setStyleSheet("background:#3e3e42;max-height:1px;");
    outer->addWidget(hline);

    auto *scroll = new QScrollArea(this);
    scroll->setWidgetResizable(true);
    scroll->setFrameShape(QFrame::NoFrame);
    scroll->setStyleSheet("background:#1e1e1e;border:none;");

    auto *content = new QWidget(scroll);
    content->setStyleSheet("background:#1e1e1e;");
    auto *cl = new QVBoxLayout(content);
    cl->setContentsMargins(20,16,20,20);
    cl->setSpacing(16);

    // Summary cards
    auto mkSec = [&](const QString &t) {
        auto *l = new QLabel(t, content);
        l->setStyleSheet("color:#8a8a8a;font-size:14px;font-weight:700;"
                         "letter-spacing:1.5px;background:transparent;");
        return l;
    };

    cl->addWidget(mkSec("MONTHLY SUMMARY"));
    auto *cardsRow = new QHBoxLayout();
    cardsRow->setSpacing(10);

    auto makeCard = [&](const QString &lbl, QLabel *&val,
                        const QString &color="#cccccc") {
        auto *c = new QWidget(content);
        c->setObjectName("StatCard");
        c->setMinimumWidth(130);
        auto *cv = new QVBoxLayout(c);
        cv->setContentsMargins(14,10,14,10);
        cv->setSpacing(4);
        auto *ll2 = new QLabel(lbl, c);
        ll2->setStyleSheet("color:#8a8a8a;font-size:14px;font-weight:700;"
                           "letter-spacing:1px;background:transparent;");
        val = new QLabel("-", c);
        val->setStyleSheet(
            QString("color:%1;font-size:18px;font-weight:600;"
                    "background:transparent;").arg(color));
        cv->addWidget(ll2); cv->addWidget(val);
        cardsRow->addWidget(c, 1);
    };

    makeCard("USED THIS MONTH", m_cardUsed,      "#6366f1");
    makeCard("COST THIS MONTH", m_cardCost,      "#ce9178");
    makeCard("REMAINING",       m_cardRemaining, "#10b981");
    makeCard("DAYS LEFT",       m_cardDaysLeft,  "#cccccc");
    cl->addLayout(cardsRow);

    m_usageBar = new QProgressBar(content);
    m_usageBar->setFixedHeight(10);
    m_usageBar->setStyleSheet(
        "QProgressBar{background:#3e3e42;border:none;border-radius:5px;}"
        "QProgressBar::chunk{background:#6366f1;border-radius:5px;}");
    cl->addWidget(m_usageBar);

    // Per-process table
    cl->addWidget(mkSec("COST BY PROCESS"));
    m_table = new QTableWidget(0, 5, content);
    m_table->setHorizontalHeaderLabels(
        {"PROCESS","TODAY","THIS WEEK","TOTAL COST","% USAGE"});
    m_table->setMaximumHeight(220);
    m_table->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_table->setAlternatingRowColors(true);
    m_table->setShowGrid(false);
    m_table->verticalHeader()->setVisible(false);
    m_table->verticalHeader()->setDefaultSectionSize(48);
    m_table->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
    cl->addWidget(m_table);

    // Daily cost chart
    cl->addWidget(mkSec("DAILY COST  (last 30 days)"));
    m_chart = new CostBarChart(content);
    cl->addWidget(m_chart);
    cl->addStretch();

    scroll->setWidget(content);
    outer->addWidget(scroll, 1);

    m_timer = new QTimer(this);
    m_timer->setInterval(60000);
    connect(m_timer, &QTimer::timeout, this, &CostTab::refresh);
    m_timer->start();
    refresh();
}

void CostTab::onSave()
{
    CostTracker::instance().saveSettings(
        m_rateSpinBox->value(),
        m_limitSpinBox->value());
    refresh();
}

void CostTab::refresh()
{
    updateSummary();
    updateTable();
    updateChart();
}

void CostTab::updateSummary()
{
    auto s = CostTracker::instance().getMonthlySummary();

    auto fmtGB = [](double gb) {
        return gb < 1.0 ?
            QString("%1 MB").arg(gb*1024, 0,'f',1) :
            QString("%1 GB").arg(gb, 0,'f',2);
    };

    m_cardUsed->setText(fmtGB(s.usedGB));
    m_cardCost->setText(QString("₹%1").arg(s.costInr, 0,'f',2));
    double remaining = qMax(0.0, s.limitGB - s.usedGB);
    m_cardRemaining->setText(fmtGB(remaining));
    m_cardDaysLeft->setText(QString("%1").arg(s.daysLeft));

    int pct = int(qBound(0.0, s.pctUsed, 100.0));
    m_usageBar->setValue(pct);
    QString barColor = pct > 80 ? "#ef4444" :
                       pct > 60 ? "#ce9178" : "#6366f1";
    m_usageBar->setStyleSheet(
        QString("QProgressBar{background:#3e3e42;border:none;border-radius:5px;}"
                "QProgressBar::chunk{background:%1;border-radius:5px;}")
            .arg(barColor));
}

void CostTab::updateTable()
{
    auto costs = CostTracker::instance().getProcessCosts(30);
    m_table->setRowCount(costs.size());

    for (int i = 0; i < costs.size(); ++i) {
        const auto &c = costs[i];
        auto item = [](const QString &t, const QColor &col,
                       Qt::Alignment a = Qt::AlignLeft|Qt::AlignVCenter) {
            auto *it = new QTableWidgetItem(t);
            it->setForeground(QBrush(col));
            it->setTextAlignment(a);
            it->setFlags(Qt::ItemIsEnabled|Qt::ItemIsSelectable);
            return it;
        };
        QColor nameColor = (i == 0) ? QColor("#ce9178") : QColor("#cccccc");
        auto right = Qt::AlignRight|Qt::AlignVCenter;
        m_table->setItem(i,0,item(c.process,
            nameColor));
        m_table->setItem(i,1,item(
            QString("₹%1").arg(c.todayCostInr,0,'f',3),
            QColor("#6366f1"), right));
        m_table->setItem(i,2,item(
            QString("₹%1").arg(c.weekCostInr,0,'f',2),
            QColor("#8a8a8a"), right));
        m_table->setItem(i,3,item(
            QString("₹%1").arg(c.totalCostInr,0,'f',2),
            QColor("#ce9178"), right));
        m_table->setItem(i,4,item(
            QString("%1%").arg(c.pctOfUsage,0,'f',1),
            QColor("#8a8a8a"), right));
    }
}

void CostTab::updateChart()
{
    auto totals = CostTracker::instance().getDailyCosts(30);
    m_chart->setData(totals, CostTracker::instance().rateInrPerGb());
}
