#include "TrustTab.h"
#include "Style.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QFrame>
#include <QHeaderView>
#include <QPainter>
#include <QProgressBar>

TrustTab::TrustTab(QWidget *parent) : QWidget(parent)
{
    auto *outer = new QVBoxLayout(this);
    outer->setContentsMargins(0, 0, 0, 0);
    outer->setSpacing(0);

    auto *topBar = new QWidget(this);
    topBar->setObjectName("TopBar");
    topBar->setFixedHeight(58);
    auto *tl = new QHBoxLayout(topBar);
    tl->setContentsMargins(20, 0, 20, 0);
    auto *ttl = new QLabel("Process Trust Score", topBar);
    ttl->setStyleSheet("color:#dde8f5;font-size:15px;font-weight:600;"
                       "font-family:'Ubuntu Mono';");
    m_summary = new QLabel("", topBar);
    m_summary->setStyleSheet("color:#334455;font-size:12px;"
                             "font-family:'Ubuntu Mono';");
    tl->addWidget(ttl);
    tl->addSpacing(12);
    tl->addWidget(m_summary);
    tl->addStretch();
    outer->addWidget(topBar);

    auto *div = new QFrame(this);
    div->setFrameShape(QFrame::HLine);
    div->setStyleSheet("background:#1c2530;max-height:1px;");
    outer->addWidget(div);

    // Info banner
    auto *info = new QLabel(
        "  Trust score is calculated from: executable path, anomalies, "
        "connection count, bandwidth, and known process signatures",
        this);
    info->setFixedHeight(30);
    info->setStyleSheet("background:#0a0f16;color:#334455;font-size:11px;"
                        "font-family:'Ubuntu Mono';"
                        "border-bottom:1px solid #1c2530;");
    outer->addWidget(info);

    m_table = new QTableWidget(0, 6, this);
    m_table->setHorizontalHeaderLabels(
        {"PROCESS", "GRADE", "SCORE", "EXECUTABLE", "ANOMALY", "REASONS"});
    m_table->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_table->setAlternatingRowColors(true);
    m_table->setShowGrid(false);
    m_table->verticalHeader()->setVisible(false);
    m_table->verticalHeader()->setDefaultSectionSize(40);
    m_table->horizontalHeader()->setSectionResizeMode(QHeaderView::Interactive);
    m_table->setColumnWidth(0, 130);
    m_table->setColumnWidth(1, 60);
    m_table->setColumnWidth(2, 80);
    m_table->setColumnWidth(3, 200);
    m_table->setColumnWidth(4, 90);
    m_table->horizontalHeader()->setStretchLastSection(true);
    outer->addWidget(m_table, 1);
}

void TrustTab::updateData(const QVector<ProcEntry> &procs,
                          const QVector<TrafficEntry> &conns)
{
    m_table->setRowCount(procs.size());

    int lowTrust = 0;
    auto item = [](const QString &t, const QColor &c,
                   Qt::Alignment a = Qt::AlignLeft | Qt::AlignVCenter)
        -> QTableWidgetItem *
    {
        auto*it=new QTableWidgetItem(t);
        it->setForeground(QBrush(c));
        it->setTextAlignment(a);
        it->setFlags(Qt::ItemIsEnabled|Qt::ItemIsSelectable);
        return it; };

    for (int i = 0; i < procs.size(); ++i)
    {
        TrustScore ts = TrustScorer::instance().score(procs[i], conns);
        if (ts.score < 60)
            lowTrust++;

        QColor gradeColor = ts.color;
        QColor scoreColor = ts.color;

        // Grade badge style
        QString exe = procs[i].exe;
        if (exe.length() > 35)
            exe = "..." + exe.right(32);

        m_table->setItem(i, 0, item(ts.process, QColor("#dde8f5")));

        // Grade as styled item
        auto *gradeItem = new QTableWidgetItem(ts.grade);
        gradeItem->setForeground(QBrush(gradeColor));
        gradeItem->setTextAlignment(Qt::AlignCenter | Qt::AlignVCenter);
        gradeItem->setFlags(Qt::ItemIsEnabled | Qt::ItemIsSelectable);
        QFont gf("Ubuntu Mono");
        gf.setPixelSize(16);
        gf.setWeight(QFont::Bold);
        gradeItem->setFont(gf);
        m_table->setItem(i, 1, gradeItem);

        // Score with progress bar widget
        auto *scoreW = new QWidget(m_table);
        auto *sl = new QHBoxLayout(scoreW);
        sl->setContentsMargins(6, 6, 6, 6);
        sl->setSpacing(6);
        auto *bar = new QProgressBar(scoreW);
        bar->setRange(0, 100);
        bar->setValue(ts.score);
        bar->setFixedHeight(10);
        bar->setTextVisible(false);
        bar->setStyleSheet(
            QString("QProgressBar{background:#1c2530;border:none;border-radius:5px;}"
                    "QProgressBar::chunk{background:%1;border-radius:5px;}")
                .arg(ts.color.name()));
        auto *numL = new QLabel(QString::number(ts.score), scoreW);
        numL->setStyleSheet(
            QString("color:%1;font-size:12px;font-family:'Ubuntu Mono';"
                    "background:transparent;")
                .arg(ts.color.name()));
        numL->setFixedWidth(28);
        sl->addWidget(bar, 1);
        sl->addWidget(numL);
        m_table->setCellWidget(i, 2, scoreW);

        m_table->setItem(i, 3, item(exe, QColor("#334455")));
        m_table->setItem(i, 4, item(procs[i].anomalyStr.isEmpty() ? "Clean" : procs[i].anomalyStr, procs[i].hasAnomaly() ? QColor("#f04040") : QColor("#20d060")));
        m_table->setItem(i, 5, item(ts.reasons.isEmpty() ? "Standard process" : ts.reasons.join(" · "), QColor("#6e8399")));

        // Row background for low trust
        if (ts.score < 40)
        {
            for (int col = 0; col < 6; ++col)
                if (m_table->item(i, col))
                    m_table->item(i, col)->setBackground(
                        QBrush(QColor("#1f0808")));
        }
    }

    m_summary->setText(
        QString("%1 processes  |  %2 low trust")
            .arg(procs.size())
            .arg(lowTrust));
}