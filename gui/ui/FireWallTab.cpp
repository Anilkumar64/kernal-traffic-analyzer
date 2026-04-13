#include "FireWallTab.h"
#include "Style.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QFrame>
#include <QHeaderView>
#include <QPushButton>
#include <QDoubleSpinBox>
#include <QLabel>
#include <QScrollArea>
#include <QTabWidget>
#include <QMessageBox>

FirewallTab::FirewallTab(QWidget *parent) : QWidget(parent)
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
    auto *ttl = new QLabel("Firewall & Throttle", topBar);
    ttl->setStyleSheet("color:#cccccc;font-size:17px;font-weight:600;"
                       "font-family:'Ubuntu Mono';");
    m_statusLabel = new QLabel("", topBar);
    m_statusLabel->setStyleSheet("color:#8a8a8a;font-size:14px;"
                                 "font-family:'Ubuntu Mono';");

    auto *unblockAll = new QPushButton("Unblock All", topBar);
    unblockAll->setFixedWidth(110);
    unblockAll->setStyleSheet(
        "QPushButton{background:#2e1515;border:1px solid #ef4444;"
        "border-radius:6px;color:#ef4444;padding:5px 10px;}"
        "QPushButton:hover{background:#ef4444;color:#cccccc;}");
    connect(unblockAll, &QPushButton::clicked, this, [this]()
            {
        FirewallManager::instance().unblockAll();
        BandwidthThrottler::instance().removeAll();
        rebuild(); });

    tl->addWidget(ttl);
    tl->addSpacing(12);
    tl->addWidget(m_statusLabel);
    tl->addStretch();
    tl->addWidget(unblockAll);
    outer->addWidget(topBar);

    auto *div = new QFrame(this);
    div->setFrameShape(QFrame::HLine);
    div->setStyleSheet("background:#3e3e42;max-height:1px;");
    outer->addWidget(div);

    // Tabs
    auto *tabs = new QTabWidget(this);
    tabs->setStyleSheet(
        "QTabWidget::pane{border:none;background:#1e1e1e;}"
        "QTabBar::tab{background:transparent;color:#8a8a8a;"
        "padding:10px 20px;border:none;"
        "border-bottom:2px solid transparent;font-size:13px;"
        "font-family:'Ubuntu Mono';}"
        "QTabBar::tab:selected{color:#cccccc;"
        "border-bottom:2px solid #6366f1;}"
        "QTabBar::tab:hover{color:#cccccc;background:#3e3e42;}");

    // Tab 1: Active Connections
    auto *connWidget = new QWidget(tabs);
    auto *cl = new QVBoxLayout(connWidget);
    cl->setContentsMargins(0, 0, 0, 0);
    auto *chdr = new QLabel(
        "  Click a connection to block its IP address", connWidget);
    chdr->setFixedHeight(40);
    chdr->setStyleSheet("background:#1a1a1a;color:#8a8a8a;"
                        "font-size:13px;font-family:'Ubuntu Mono';"
                        "border-bottom:1px solid #555555;");
    cl->addWidget(chdr);
    m_connTable = new QTableWidget(0, 6, connWidget);
    m_connTable->setHorizontalHeaderLabels(
        {"PROCESS", "DOMAIN / IP", "DEST IP", "PORT", "PROTO", "ACTION"});
    m_connTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_connTable->setAlternatingRowColors(true);
    m_connTable->setShowGrid(false);
    m_connTable->verticalHeader()->setVisible(false);
    m_connTable->verticalHeader()->setDefaultSectionSize(46);
    m_connTable->horizontalHeader()->setSectionResizeMode(QHeaderView::Interactive);
    m_connTable->setColumnWidth(0, 120);
    m_connTable->setColumnWidth(1, 200);
    m_connTable->setColumnWidth(2, 130);
    m_connTable->setColumnWidth(3, 60);
    m_connTable->setColumnWidth(4, 60);
    m_connTable->setColumnWidth(5, 100);
    cl->addWidget(m_connTable, 1);
    tabs->addTab(connWidget, "Active Connections");

    // Tab 2: Firewall Rules
    auto *rulesWidget = new QWidget(tabs);
    auto *rl = new QVBoxLayout(rulesWidget);
    rl->setContentsMargins(0, 0, 0, 0);
    auto *rhdr = new QLabel(
        "  Current iptables OUTPUT rules added by KTA", rulesWidget);
    rhdr->setFixedHeight(40);
    rhdr->setStyleSheet("background:#1a1a1a;color:#8a8a8a;"
                        "font-size:13px;font-family:'Ubuntu Mono';"
                        "border-bottom:1px solid #555555;");
    rl->addWidget(rhdr);
    m_rulesTable = new QTableWidget(0, 5, rulesWidget);
    m_rulesTable->setHorizontalHeaderLabels(
        {"DEST IP", "PORT", "PROTO", "COMMENT", "ACTION"});
    m_rulesTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_rulesTable->setAlternatingRowColors(true);
    m_rulesTable->setShowGrid(false);
    m_rulesTable->verticalHeader()->setVisible(false);
    m_rulesTable->verticalHeader()->setDefaultSectionSize(46);
    m_rulesTable->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
    rl->addWidget(m_rulesTable, 1);
    tabs->addTab(rulesWidget, "Firewall Rules");

    // Tab 3: Bandwidth Throttle
    auto *throttleWidget = new QWidget(tabs);
    auto *ttl2 = new QVBoxLayout(throttleWidget);
    ttl2->setContentsMargins(0, 0, 0, 0);
    auto *thdr = new QLabel(
        "  Set bandwidth limits per process (requires root + tc)", throttleWidget);
    thdr->setFixedHeight(40);
    thdr->setStyleSheet("background:#1a1a1a;color:#8a8a8a;"
                        "font-size:13px;font-family:'Ubuntu Mono';"
                        "border-bottom:1px solid #555555;");
    ttl2->addWidget(thdr);
    m_throttleTable = new QTableWidget(0, 4, throttleWidget);
    m_throttleTable->setHorizontalHeaderLabels(
        {"PROCESS", "CURRENT RATE", "LIMIT", "ACTION"});
    m_throttleTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_throttleTable->setAlternatingRowColors(true);
    m_throttleTable->setShowGrid(false);
    m_throttleTable->verticalHeader()->setVisible(false);
    m_throttleTable->verticalHeader()->setDefaultSectionSize(48);
    m_throttleTable->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
    ttl2->addWidget(m_throttleTable, 1);
    tabs->addTab(throttleWidget, "Bandwidth Throttle");

    outer->addWidget(tabs, 1);

    connect(&FirewallManager::instance(), &FirewallManager::rulesChanged,
            this, &FirewallTab::onRulesChanged);
}

void FirewallTab::updateData(const QVector<TrafficEntry> &conns,
                             const QVector<ProcEntry> &procs)
{
    m_conns = conns;
    m_procs = procs;
    rebuild();
}

void FirewallTab::onRulesChanged()
{
    rebuild();
}

void FirewallTab::rebuild()
{
    // Active connections table
    QVector<TrafficEntry> active;
    QSet<QString> seen;
    for (const auto &e : m_conns)
    {
        if (!e.isActive())
            continue;
        QString key = e.destIp + ":" + QString::number(e.destPort);
        if (seen.contains(key))
            continue;
        seen.insert(key);
        active.append(e);
    }

    m_connTable->setRowCount(active.size());
    auto item = [](const QString &t, const QColor &c) -> QTableWidgetItem *
    {
        auto*it=new QTableWidgetItem(t);
        it->setForeground(QBrush(c));
        it->setFlags(Qt::ItemIsEnabled|Qt::ItemIsSelectable);
        return it; };

    bool fwAvail = FirewallManager::isAvailable();

    for (int i = 0; i < active.size(); ++i)
    {
        const TrafficEntry &e = active[i];
        QString dom = (e.domain.isEmpty() || e.domain == "-") ? e.destIp : e.domain;
        bool blocked = FirewallManager::instance().isBlocked(e.destIp);

        m_connTable->setItem(i, 0, item(e.process, QColor("#cccccc")));
        m_connTable->setItem(i, 1, item(dom, QColor("#6366f1")));
        m_connTable->setItem(i, 2, item(e.destIp, QColor("#8a8a8a")));
        m_connTable->setItem(i, 3, item(QString::number(e.destPort), QColor("#8a8a8a")));
        m_connTable->setItem(i, 4, item(e.protocol, QColor("#8a8a8a")));

        // Action button
        auto *btn = new QPushButton(blocked ? "Unblock" : "Block", m_connTable);
        QString ip = e.destIp;
        QString proc = e.process;
        if (blocked)
        {
            btn->setStyleSheet(
                "QPushButton{background:#0a2318;border:1px solid #10b981;"
                "border-radius:5px;color:#10b981;padding:4px 8px;font-size:11px;"
                "font-family:'Ubuntu Mono';}"
                "QPushButton:hover{background:#10b981;color:#252526;}");
            connect(btn, &QPushButton::clicked, this, [ip, this]()
                    {
                for (const auto &r:FirewallManager::instance().rules())
                    if (r.destIp==ip) {
                        FirewallManager::instance().unblock(r.id);
                        break;
                    } });
        }
        else
        {
            if (!fwAvail)
                btn->setEnabled(false);
            btn->setStyleSheet(
                "QPushButton{background:#2e1515;border:1px solid #ef4444;"
                "border-radius:5px;color:#ef4444;padding:4px 8px;font-size:11px;"
                "font-family:'Ubuntu Mono';}"
                "QPushButton:hover{background:#ef4444;color:#cccccc;}"
                "QPushButton:disabled{color:#8a8a8a;border-color:#555555;}");
            connect(btn, &QPushButton::clicked, this, [ip, proc, this]()
                    {
                if (!FirewallManager::isAvailable()) {
                    QMessageBox::warning(this,"Root Required",
                        "Blocking requires root privileges.\n"
                        "Run KTA with: sudo ./kernel_traffic_analyzer");
                    return;
                }
                FirewallManager::instance().blockIp(ip,
                    QString("blocked:%1").arg(proc)); });
        }
        m_connTable->setCellWidget(i, 5, btn);
    }

    // Firewall rules table
    auto rules = FirewallManager::instance().rules();
    m_rulesTable->setRowCount(rules.size());
    for (int i = 0; i < rules.size(); ++i)
    {
        const FirewallRule &r = rules[i];
        QString port = r.destPort > 0 ? QString::number(r.destPort) : "all";
        QString proto = r.protocol.isEmpty() ? "all" : r.protocol;

        m_rulesTable->setItem(i, 0, item(r.destIp, QColor("#ef4444")));
        m_rulesTable->setItem(i, 1, item(port, QColor("#8a8a8a")));
        m_rulesTable->setItem(i, 2, item(proto, QColor("#8a8a8a")));
        m_rulesTable->setItem(i, 3, item(r.comment, QColor("#8a8a8a")));

        auto *ubtn = new QPushButton("Unblock", m_rulesTable);
        ubtn->setStyleSheet(
            "QPushButton{background:#0a2318;border:1px solid #10b981;"
            "border-radius:5px;color:#10b981;padding:4px 8px;font-size:11px;"
            "font-family:'Ubuntu Mono';}"
            "QPushButton:hover{background:#10b981;color:#252526;}");
        QString rid = r.id;
        connect(ubtn, &QPushButton::clicked, this, [rid]()
                { FirewallManager::instance().unblock(rid); });
        m_rulesTable->setCellWidget(i, 4, ubtn);
    }

    // Status
    bool tcAvail = BandwidthThrottler::isAvailable();
    m_statusLabel->setText(
        QString("iptables: %1  |  tc: %2  |  Rules: %3")
            .arg(fwAvail ? "ready" : "need root")
            .arg(tcAvail ? "ready" : "not found")
            .arg(rules.size()));

    rebuildThrottleTable();
}

void FirewallTab::rebuildThrottleTable()
{
    bool tcAvail = BandwidthThrottler::isAvailable();
    m_throttleTable->setRowCount(m_procs.size());

    auto fmtR = [](quint32 b) -> QString
    {
        if(b<1024)return QString("%1B/s").arg(b);
        if(b<1048576)return QString("%1KB/s").arg(b/1024.0,0,'f',1);
        return QString("%1MB/s").arg(b/1048576.0,0,'f',1); };

    auto item = [](const QString &t, const QColor &c) -> QTableWidgetItem *
    {
        auto*it=new QTableWidgetItem(t);
        it->setForeground(QBrush(c));
        it->setFlags(Qt::ItemIsEnabled|Qt::ItemIsSelectable);
        return it; };

    for (int i = 0; i < m_procs.size(); ++i)
    {
        const ProcEntry &p = m_procs[i];
        bool throttled = BandwidthThrottler::instance().isThrottled(p.process);
        quint32 limit = BandwidthThrottler::instance().getLimit(p.process);

        m_throttleTable->setItem(i, 0, item(p.process, QColor("#cccccc")));
        m_throttleTable->setItem(i, 1, item(fmtR(p.rateOutBps + p.rateInBps), QColor("#8a8a8a")));
        m_throttleTable->setItem(i, 2, item(throttled ? fmtR(limit * 1024) : "Unlimited", throttled ? QColor("#ce9178") : QColor("#10b981")));

        auto *row = new QWidget(m_throttleTable);
        auto *rl = new QHBoxLayout(row);
        rl->setContentsMargins(4, 2, 4, 2);
        rl->setSpacing(6);

        auto *spin = new QDoubleSpinBox(row);
        spin->setRange(10, 100000);
        spin->setValue(throttled ? limit : 1000);
        spin->setSuffix(" KB/s");
        spin->setFixedWidth(110);
        spin->setEnabled(tcAvail);

        auto *setBtn = new QPushButton("Limit", row);
        setBtn->setFixedWidth(60);
        setBtn->setEnabled(tcAvail);
        setBtn->setStyleSheet(
            "QPushButton{background:#2e1f15;border:1px solid #ce9178;"
            "border-radius:5px;color:#ce9178;padding:3px 6px;font-size:11px;"
            "font-family:'Ubuntu Mono';}"
            "QPushButton:hover{background:#ce9178;color:#252526;}"
            "QPushButton:disabled{color:#8a8a8a;border-color:#555555;}");

        QString proc = p.process;
        int pid = p.pid;
        connect(setBtn, &QPushButton::clicked, this, [proc, pid, spin]()
                { BandwidthThrottler::instance().setLimit(
                      proc, pid, quint32(spin->value())); });

        auto *clearBtn = new QPushButton("Clear", row);
        clearBtn->setFixedWidth(55);
        clearBtn->setEnabled(throttled && tcAvail);
        clearBtn->setStyleSheet(
            "QPushButton{background:#252526;border:1px solid #555555;"
            "border-radius:5px;color:#8a8a8a;padding:3px 6px;font-size:11px;"
            "font-family:'Ubuntu Mono';}"
            "QPushButton:hover{background:#555555;color:#cccccc;}"
            "QPushButton:disabled{opacity:0.4;}");
        connect(clearBtn, &QPushButton::clicked, this, [proc]()
                { BandwidthThrottler::instance().removeLimit(proc); });

        rl->addWidget(spin);
        rl->addWidget(setBtn);
        rl->addWidget(clearBtn);
        m_throttleTable->setCellWidget(i, 3, row);
    }
}

void FirewallTab::blockSelected() {}
void FirewallTab::unblockSelected() {}