#include "DnsLeakTab.h"
#include "Style.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QFrame>
#include <QHeaderView>
#include <QPushButton>
#include <QDateTime>

DnsLeakTab::DnsLeakTab(QWidget *parent) : QWidget(parent)
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
    auto *ttl = new QLabel("DNS Leak Detector", topBar);
    ttl->setStyleSheet("color:#1e2a3a;font-size:15px;font-weight:600;"
                       "font-family:'Ubuntu Mono';");

    auto *clearBtn = new QPushButton("Clear Events", topBar);
    clearBtn->setFixedWidth(120);
    connect(clearBtn, &QPushButton::clicked, this, [this]() {
        if (m_detector) { m_detector->clearEvents(); rebuild(); }
    });

    tl->addWidget(ttl); tl->addStretch(); tl->addWidget(clearBtn);
    outer->addWidget(topBar);

    auto *div = new QFrame(this);
    div->setFrameShape(QFrame::HLine);
    div->setStyleSheet("background:#e4e8ee;max-height:1px;");
    outer->addWidget(div);

    // Status banner
    m_statusBanner = new QLabel("Initializing...", this);
    m_statusBanner->setFixedHeight(44);
    m_statusBanner->setAlignment(Qt::AlignCenter);
    m_statusBanner->setStyleSheet(
        "background:#f0fdf4;color:#10b981;font-size:14px;font-weight:600;"
        "font-family:'Ubuntu Mono';border-bottom:1px solid #e4e8ee;");
    outer->addWidget(m_statusBanner);

    // Authorized resolvers
    auto *resolverWidget = new QWidget(this);
    resolverWidget->setFixedHeight(40);
    resolverWidget->setStyleSheet("background:#f7f8fa;");
    auto *rl = new QHBoxLayout(resolverWidget);
    rl->setContentsMargins(20,0,20,0);
    auto *rlbl = new QLabel("Authorized resolvers:", resolverWidget);
    rlbl->setStyleSheet("color:#9ba8b6;font-size:11px;font-weight:700;"
                        "font-family:'Ubuntu Mono';letter-spacing:1px;");
    m_resolverList = new QLabel("loading...", resolverWidget);
    m_resolverList->setStyleSheet("color:#10b981;font-size:12px;"
                                   "font-family:'Ubuntu Mono';");
    rl->addWidget(rlbl); rl->addWidget(m_resolverList); rl->addStretch();
    outer->addWidget(resolverWidget);

    auto *div2 = new QFrame(this);
    div2->setFrameShape(QFrame::HLine);
    div2->setStyleSheet("background:#e4e8ee;max-height:1px;");
    outer->addWidget(div2);

    // Events table
    m_table = new QTableWidget(0, 6, this);
    m_table->setHorizontalHeaderLabels(
        {"TIME","PROCESS","PID","DEST IP","SEVERITY","REASON"});
    m_table->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_table->setAlternatingRowColors(true);
    m_table->setShowGrid(false);
    m_table->verticalHeader()->setVisible(false);
    m_table->verticalHeader()->setDefaultSectionSize(34);
    m_table->horizontalHeader()->setSectionResizeMode(QHeaderView::Interactive);
    m_table->setColumnWidth(0, 90);
    m_table->setColumnWidth(1, 130);
    m_table->setColumnWidth(2, 60);
    m_table->setColumnWidth(3, 130);
    m_table->setColumnWidth(4, 90);
    m_table->horizontalHeader()->setStretchLastSection(true);
    outer->addWidget(m_table, 1);
}

void DnsLeakTab::setDetector(DnsLeakDetector *detector)
{
    m_detector = detector;
    connect(detector, &DnsLeakDetector::eventsChanged,
            this, &DnsLeakTab::onEventsChanged);
    rebuild();
}

void DnsLeakTab::onEventsChanged()
{
    rebuild();
}

void DnsLeakTab::rebuild()
{
    if (!m_detector) return;

    auto events = m_detector->events();
    int critCount = 0;
    for (const auto &e : events)
        if (e.severity == LeakSeverity::Critical) critCount++;

    if (critCount > 0) {
        m_statusBanner->setText(
            QString("⚠  %1 DNS leak(s) detected").arg(critCount));
        m_statusBanner->setStyleSheet(
            "background:#fef2f2;color:#ef4444;font-size:14px;font-weight:600;"
            "font-family:'Ubuntu Mono';border-bottom:1px solid #e4e8ee;");
    } else if (!events.isEmpty()) {
        m_statusBanner->setText(
            QString("⚠  %1 suspicious DNS event(s)").arg(events.size()));
        m_statusBanner->setStyleSheet(
            "background:#fffbeb;color:#f59e0b;font-size:14px;font-weight:600;"
            "font-family:'Ubuntu Mono';border-bottom:1px solid #e4e8ee;");
    } else {
        m_statusBanner->setText("✓  No DNS leaks detected");
        m_statusBanner->setStyleSheet(
            "background:#f0fdf4;color:#10b981;font-size:14px;font-weight:600;"
            "font-family:'Ubuntu Mono';border-bottom:1px solid #e4e8ee;");
    }

    // Resolvers
    QStringList resolvers = m_detector->authorizedResolvers();
    m_resolverList->setText(resolvers.join("  ·  "));

    // Table
    m_table->setRowCount(events.size());
    for (int i = 0; i < events.size(); ++i) {
        const DnsLeakEvent &ev = events[i];

        auto item = [](const QString &t, const QColor &c) {
            auto *it = new QTableWidgetItem(t);
            it->setForeground(QBrush(c));
            it->setFlags(Qt::ItemIsEnabled|Qt::ItemIsSelectable);
            return it;
        };

        QColor severityColor =
            ev.severity == LeakSeverity::Critical ? QColor("#ef4444") :
            ev.severity == LeakSeverity::Warning  ? QColor("#f59e0b") :
                                                     QColor("#5c6b7f");
        QColor rowBg =
            ev.severity == LeakSeverity::Critical ? QColor("#fef2f2") :
            ev.severity == LeakSeverity::Warning  ? QColor("#fffbeb") :
                                                     QColor("#ffffff");

        QString time = QDateTime::fromSecsSinceEpoch(ev.timestamp)
                           .toString("hh:mm:ss");

        for (int col = 0; col < 6; ++col) {
            QTableWidgetItem *it = nullptr;
            switch (col) {
            case 0: it = item(time,              QColor("#5c6b7f")); break;
            case 1: it = item(ev.process,        QColor("#1e2a3a")); break;
            case 2: it = item(QString::number(ev.pid), QColor("#9ba8b6")); break;
            case 3: it = item(ev.destIp,         QColor("#6366f1")); break;
            case 4: it = item(ev.severityStr(),  severityColor); break;
            case 5: it = item(ev.reason,         QColor("#5c6b7f")); break;
            }
            if (it) {
                it->setBackground(QBrush(rowBg));
                m_table->setItem(i, col, it);
            }
        }
    }
}
