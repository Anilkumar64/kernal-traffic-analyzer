#include "BgpTab.h"
#include "Style.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QFrame>
#include <QHeaderView>
#include <QPushButton>
#include <QDateTime>

BgpTab::BgpTab(QWidget *parent) : QWidget(parent)
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
    auto *ttl = new QLabel("BGP Route Monitor", topBar);
    ttl->setStyleSheet("color:#dde8f5;font-size:15px;font-weight:600;"
                       "font-family:'Ubuntu Mono';");

    m_resetBtn = new QPushButton("Reset Learning", topBar);
    m_resetBtn->setFixedWidth(140);

    tl->addWidget(ttl); tl->addStretch(); tl->addWidget(m_resetBtn);
    outer->addWidget(topBar);

    auto *div = new QFrame(this);
    div->setFrameShape(QFrame::HLine);
    div->setStyleSheet("background:#1c2530;max-height:1px;");
    outer->addWidget(div);

    // Learning/Status banner
    m_statusBanner = new QLabel("", this);
    m_statusBanner->setFixedHeight(44);
    m_statusBanner->setAlignment(Qt::AlignCenter);
    m_statusBanner->setStyleSheet(
        "background:#0a1828;color:#5aabff;font-size:13px;font-weight:600;"
        "font-family:'Ubuntu Mono';border-bottom:1px solid #1c2530;");
    outer->addWidget(m_statusBanner);

    // Learned routes section
    auto mkSec = [&](const QString &t) {
        auto *w = new QWidget(this);
        w->setFixedHeight(30);
        w->setStyleSheet("background:#0a0f16;");
        auto *l = new QLabel(t, w);
        l->setObjectName("SectionTitle");
        auto *ll = new QHBoxLayout(w);
        ll->setContentsMargins(20,0,20,0);
        ll->addWidget(l);
        ll->addStretch();
        return w;
    };

    outer->addWidget(mkSec("LEARNED ROUTES"));

    m_learnedTable = new QTableWidget(0, 5, this);
    m_learnedTable->setHorizontalHeaderLabels(
        {"DOMAIN","NORMAL PATH","COUNTRIES","TIMES SEEN","STATUS"});
    m_learnedTable->setMaximumHeight(200);
    m_learnedTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_learnedTable->setAlternatingRowColors(true);
    m_learnedTable->setShowGrid(false);
    m_learnedTable->verticalHeader()->setVisible(false);
    m_learnedTable->verticalHeader()->setDefaultSectionSize(32);
    m_learnedTable->horizontalHeader()->setSectionResizeMode(QHeaderView::Interactive);
    m_learnedTable->setColumnWidth(0, 200);
    m_learnedTable->setColumnWidth(1, 160);
    m_learnedTable->setColumnWidth(2, 120);
    m_learnedTable->setColumnWidth(3, 90);
    m_learnedTable->horizontalHeader()->setStretchLastSection(true);
    outer->addWidget(m_learnedTable);

    outer->addWidget(mkSec("ALERT LOG"));

    m_alertTable = new QTableWidget(0, 5, this);
    m_alertTable->setHorizontalHeaderLabels(
        {"TIME","DOMAIN","EXPECTED PATH","ACTUAL PATH","RISK"});
    m_alertTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_alertTable->setAlternatingRowColors(true);
    m_alertTable->setShowGrid(false);
    m_alertTable->verticalHeader()->setVisible(false);
    m_alertTable->verticalHeader()->setDefaultSectionSize(32);
    m_alertTable->horizontalHeader()->setSectionResizeMode(QHeaderView::Interactive);
    m_alertTable->setColumnWidth(0, 90);
    m_alertTable->setColumnWidth(1, 180);
    m_alertTable->setColumnWidth(2, 160);
    m_alertTable->setColumnWidth(3, 160);
    m_alertTable->horizontalHeader()->setStretchLastSection(true);
    outer->addWidget(m_alertTable, 1);
}

void BgpTab::setMonitor(BgpMonitor *monitor)
{
    m_monitor = monitor;
    connect(monitor, &BgpMonitor::dataChanged,
            this, &BgpTab::onDataChanged);
    connect(m_resetBtn, &QPushButton::clicked, this, [this]() {
        // Clear learned routes by reinitializing
        if (m_monitor) {
            m_monitor->stop();
            m_monitor->start();
            rebuild();
        }
    });
    rebuild();
}

void BgpTab::onDataChanged()
{
    rebuild();
}

void BgpTab::rebuild()
{
    if (!m_monitor) return;

    bool learning = m_monitor->isLearning();
    int  days     = m_monitor->learningDaysComplete();

    if (learning) {
        m_statusBanner->setText(
            QString("Learning mode — %1 / 7 days complete  "
                    "(monitoring continues in background)")
                .arg(days));
        m_statusBanner->setStyleSheet(
            "background:#0a1828;color:#5aabff;font-size:13px;font-weight:600;"
            "font-family:'Ubuntu Mono';border-bottom:1px solid #1c2530;");
    } else {
        auto alerts = m_monitor->alerts();
        if (!alerts.isEmpty()) {
            m_statusBanner->setText(
                QString("⚠  %1 BGP anomal%2 detected")
                    .arg(alerts.size())
                    .arg(alerts.size()==1?"y":"ies"));
            m_statusBanner->setStyleSheet(
                "background:#1f0808;color:#f04040;font-size:13px;font-weight:600;"
                "font-family:'Ubuntu Mono';border-bottom:1px solid #1c2530;");
        } else {
            m_statusBanner->setText("✓  All routes normal — no BGP anomalies");
            m_statusBanner->setStyleSheet(
                "background:#081f12;color:#20d060;font-size:13px;font-weight:600;"
                "font-family:'Ubuntu Mono';border-bottom:1px solid #1c2530;");
        }
    }

    // Learned routes
    auto learned = m_monitor->learnedRoutes();
    m_learnedTable->setRowCount(learned.size());
    int row = 0;
    for (auto it = learned.begin(); it != learned.end(); ++it, ++row) {
        const DomainFingerprints &df = it.value();

        auto item = [](const QString &t, const QColor &c) {
            auto *it2 = new QTableWidgetItem(t);
            it2->setForeground(QBrush(c));
            it2->setFlags(Qt::ItemIsEnabled|Qt::ItemIsSelectable);
            return it2;
        };

        // Best fingerprint (most common)
        int totalCount = 0;
        QStringList bestCountries;
        QStringList bestAsns;
        for (const auto &fp : df.prints) {
            if (fp.count > totalCount) {
                totalCount = fp.count;
                bestCountries = QStringList(fp.countries.begin(), fp.countries.end());
                for (int a : fp.asns) bestAsns << QString::number(a);
            }
        }

        QString status = learning ? "Learning" :
                         (totalCount > 10) ? "Stable" : "Learning";
        QColor statusColor = (status == "Stable") ? QColor("#20d060") :
                                                     QColor("#f0b800");

        m_learnedTable->setItem(row,0,item(df.domain, QColor("#5aabff")));
        m_learnedTable->setItem(row,1,item(bestAsns.join("→"), QColor("#6e8399")));
        m_learnedTable->setItem(row,2,item(bestCountries.join("→"), QColor("#dde8f5")));
        m_learnedTable->setItem(row,3,item(QString::number(totalCount), QColor("#334455")));
        m_learnedTable->setItem(row,4,item(status, statusColor));
    }

    // Alert log
    auto alerts = m_monitor->alerts();
    m_alertTable->setRowCount(alerts.size());
    for (int i = 0; i < alerts.size(); ++i) {
        const BgpAlert &a = alerts[i];

        auto item = [](const QString &t, const QColor &c) {
            auto *it2 = new QTableWidgetItem(t);
            it2->setForeground(QBrush(c));
            it2->setFlags(Qt::ItemIsEnabled|Qt::ItemIsSelectable);
            it2->setBackground(QBrush(QColor("#1f0808")));
            return it2;
        };

        QString time = QDateTime::fromSecsSinceEpoch(a.timestamp)
                           .toString("hh:mm:ss");
        QColor riskColor = (a.risk=="HIGH") ? QColor("#f04040") : QColor("#f0b800");

        m_alertTable->setItem(i,0,item(time, QColor("#6e8399")));
        m_alertTable->setItem(i,1,item(a.domain, QColor("#5aabff")));
        m_alertTable->setItem(i,2,item(a.expectedCountries.join("→"), QColor("#6e8399")));
        m_alertTable->setItem(i,3,item(a.actualCountries.join("→"), QColor("#f04040")));
        m_alertTable->setItem(i,4,item(a.risk, riskColor));
    }
}
