#include "Sidebar.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QFrame>
#include <QPropertyAnimation>

// ── Per-state button styles ───────────────────────────────────────────

static const QString STYLE_ACTIVE =
    "QPushButton {"
    "  background: qlineargradient(x1:0,y1:0,x2:1,y2:0,"
    "    stop:0 #052030, stop:1 #1e1e1e);"
    "  color: #3794ff;"
    "  border: none;"
    "  border-left: 2px solid #3794ff;"
    "  text-align: left;"
    "  padding: 11px 16px 11px 14px;"
    "  font-size: 14px;"
    "  font-family: 'JetBrains Mono', 'Ubuntu Mono', monospace;"
    "  font-weight: 600;"
    "}";

static const QString STYLE_INACTIVE =
    "QPushButton {"
    "  background: transparent;"
    "  color: #8a8a8a;"
    "  border: none;"
    "  text-align: left;"
    "  padding: 11px 16px;"
    "  font-size: 14px;"
    "  font-family: 'JetBrains Mono', 'Ubuntu Mono', monospace;"
    "  font-weight: 400;"
    "}"
    "QPushButton:hover {"
    "  background-color: #252526;"
    "  color: #cccccc;"
    "  border-left: 2px solid #555555;"
    "  padding-left: 16px;"
    "}";

static const QString STYLE_ACTIVE_ICON =
    "QPushButton {"
    "  background: qlineargradient(x1:0,y1:0,x2:1,y2:0,"
    "    stop:0 #052030, stop:1 #1e1e1e);"
    "  color: #3794ff;"
    "  border: none;"
    "  border-left: 2px solid #3794ff;"
    "  text-align: center;"
    "  padding: 10px 4px;"
    "  font-size: 15px;"
    "  font-family: 'JetBrains Mono', 'Ubuntu Mono', monospace;"
    "}";

static const QString STYLE_INACTIVE_ICON =
    "QPushButton {"
    "  background: transparent;"
    "  color: #555555;"
    "  border: none;"
    "  text-align: center;"
    "  padding: 10px 4px;"
    "  font-size: 15px;"
    "  font-family: 'JetBrains Mono', 'Ubuntu Mono', monospace;"
    "}"
    "QPushButton:hover {"
    "  background-color: #252526;"
    "  color: #3794ff;"
    "}";

// ── Icons for each page ───────────────────────────────────────────────
//    Using Unicode box-drawing / misc symbols that render in mono fonts

static const char *ICONS[] = {
    "⇄", // Connections
    "▤", // Processes
    "◈", // Route Map
    "◎", // DNS Map
    "⚠", // Anomalies
    "⇅", // Bandwidth Load
    "▦", // History
    "◇", // Cost
    "⏱", // Timeline
    "⛨", // DNS Leaks
    "⬡", // BGP
    "◉", // Net Perf
    "⊕", // Threat Map
    "⛉", // Firewall
    "◐", // Trust
};

Sidebar::Sidebar(QWidget *parent) : QWidget(parent)
{
    setObjectName("Sidebar");
    setFixedWidth(EXPANDED_W);

    auto *layout = new QVBoxLayout(this);
    layout->setContentsMargins(0, 0, 0, 0);
    layout->setSpacing(0);

    // ── Logo / header ─────────────────────────────────────────────
    m_logoWidget = new QWidget(this);
    m_logoWidget->setObjectName("SidebarLogo");
    m_logoWidget->setFixedHeight(70);
    m_logoWidget->setStyleSheet("background:#252526; border-bottom:1px solid #333333;");

    auto *ll = new QHBoxLayout(m_logoWidget);
    ll->setContentsMargins(14, 0, 10, 0);
    ll->setSpacing(0);

    // Cyan square accent
    auto *accent = new QLabel(m_logoWidget);
    accent->setFixedSize(8, 26);
    accent->setStyleSheet(
        "background: qlineargradient(x1:0,y1:0,x2:0,y2:1,"
        " stop:0 #3794ff, stop:1 #3794ff);"
        "border-radius:2px;");

    auto *textCol = new QVBoxLayout();
    textCol->setSpacing(1);
    textCol->setContentsMargins(10, 0, 0, 0);

    m_titleLabel = new QLabel("KTA", m_logoWidget);
    m_titleLabel->setStyleSheet(
        "color:#cccccc; font-size:16px; font-weight:700;"
        "letter-spacing:3px; background:transparent;");

    m_subLabel = new QLabel("kernel traffic analyzer", m_logoWidget);
    m_subLabel->setStyleSheet(
        "color:#555555; font-size:11px; letter-spacing:0.5px;"
        "background:transparent;");

    textCol->addWidget(m_titleLabel);
    textCol->addWidget(m_subLabel);

    m_btnCollapse = new QPushButton("◀", m_logoWidget);
    m_btnCollapse->setObjectName("CollapseBtn");
    m_btnCollapse->setFixedSize(22, 22);
    m_btnCollapse->setCursor(Qt::PointingHandCursor);
    m_btnCollapse->setStyleSheet(
        "QPushButton{"
        "  background:transparent; border:1px solid #333333;"
        "  border-radius:4px; color:#555555; font-size:10px;"
        "}"
        "QPushButton:hover{"
        "  color:#3794ff; border-color:#3794ff;"
        "}");
    connect(m_btnCollapse, &QPushButton::clicked, this, &Sidebar::toggleCollapse);

    ll->addWidget(accent);
    ll->addLayout(textCol, 1);
    ll->addWidget(m_btnCollapse);
    layout->addWidget(m_logoWidget);

    // ── Helpers ───────────────────────────────────────────────────
    auto mkDiv = [&]()
    {
        auto *f = new QFrame(this);
        f->setFrameShape(QFrame::HLine);
        f->setStyleSheet("background:#333333; max-height:1px; border:none;");
        return f;
    };
    auto mkSec = [&](const QString &t)
    {
        auto *l = new QLabel(t, this);
        l->setObjectName("SectionTitle");
        l->setStyleSheet(
            "color:#555555; font-size:11px; font-weight:700;"
            "letter-spacing:2px; padding:10px 16px 3px 16px;"
            "background:transparent;");
        return l;
    };

    // ── MONITOR section ───────────────────────────────────────────
    layout->addWidget(mkDiv());
    layout->addWidget(mkSec("MONITOR"));

    m_btnConnections = makeNavButton("Connections", ICONS[0], PAGE_CONNECTIONS);
    m_btnProcesses = makeNavButton("Processes", ICONS[1], PAGE_PROCESSES);
    m_btnRouteMap = makeNavButton("Route Map", ICONS[2], PAGE_ROUTEMAP);
    m_btnLoadBalancer = makeNavButton("Bandwidth Load", ICONS[5], PAGE_LOADBALANCER);
    m_btnTimeline = makeNavButton("Timeline", ICONS[8], PAGE_TIMELINE);
    m_btnHistory = makeNavButton("History", ICONS[6], PAGE_HISTORY);
    m_btnNetworkPerf = makeNavButton("Net Perf", ICONS[11], PAGE_NETWORKPERF);

    layout->addWidget(m_btnConnections);
    layout->addWidget(m_btnProcesses);
    layout->addWidget(m_btnRouteMap);
    layout->addWidget(m_btnLoadBalancer);
    layout->addWidget(m_btnTimeline);
    layout->addWidget(m_btnHistory);
    layout->addWidget(m_btnNetworkPerf);

    // ── INTELLIGENCE section ──────────────────────────────────────
    layout->addWidget(mkDiv());
    layout->addWidget(mkSec("INTELLIGENCE"));

    m_btnDns = makeNavButton("DNS Map", ICONS[3], PAGE_DNS);
    m_btnDnsLeak = makeNavButton("DNS Leaks", ICONS[9], PAGE_DNSLEAK);
    m_btnBgp = makeNavButton("BGP Monitor", ICONS[10], PAGE_BGP);
    m_btnThreatMap = makeNavButton("Threat Map", ICONS[12], PAGE_THREATMAP);

    // Anomaly button with alert badge
    m_btnAnomalies = makeNavButton("Anomalies", ICONS[4], PAGE_ANOMALIES);
    auto *aRow = new QWidget(this);
    aRow->setStyleSheet("background:transparent;");
    auto *aLayout = new QHBoxLayout(aRow);
    aLayout->setContentsMargins(0, 0, 8, 0);
    aLayout->setSpacing(0);
    aLayout->addWidget(m_btnAnomalies);

    m_anomalyBadge = new QLabel(aRow);
    m_anomalyBadge->setFixedSize(18, 18);
    m_anomalyBadge->setAlignment(Qt::AlignCenter);
    m_anomalyBadge->setStyleSheet(
        "background:#f44747; color:#ffffff;"
        "border-radius:10px; border:none;"
        "font-size:11px; font-weight:700;");
    m_anomalyBadge->hide();
    aLayout->addWidget(m_anomalyBadge);

    layout->addWidget(m_btnDns);
    layout->addWidget(aRow);
    layout->addWidget(m_btnDnsLeak);
    layout->addWidget(m_btnBgp);
    layout->addWidget(m_btnThreatMap);

    // ── CONTROL section ───────────────────────────────────────────
    layout->addWidget(mkDiv());
    layout->addWidget(mkSec("CONTROL"));

    m_btnFirewall = makeNavButton("Firewall", ICONS[13], PAGE_FIREWALL);
    m_btnTrust = makeNavButton("Trust", ICONS[14], PAGE_TRUST);
    m_btnCost = makeNavButton("Data Cost", ICONS[7], PAGE_COST);

    layout->addWidget(m_btnFirewall);
    layout->addWidget(m_btnTrust);
    layout->addWidget(m_btnCost);

    layout->addStretch();
    layout->addWidget(mkDiv());

    // ── Live status footer ────────────────────────────────────────
    auto *statusW = new QWidget(this);
    statusW->setFixedHeight(48);
    statusW->setStyleSheet("background:#252526;");
    auto *sl = new QHBoxLayout(statusW);
    sl->setContentsMargins(14, 0, 14, 0);
    sl->setSpacing(8);

    auto *liveDot = new QLabel(statusW);
    liveDot->setFixedSize(6, 6);
    liveDot->setStyleSheet("background:#4ec9b0; border-radius:4px;");

    m_liveLabel = new QLabel("LIVE  ·  v6.0", statusW);
    m_liveLabel->setStyleSheet(
        "color:#4ec9b0; font-size:13px; letter-spacing:1px;"
        "background:transparent;");

    sl->addWidget(liveDot);
    sl->addWidget(m_liveLabel);
    sl->addStretch();
    layout->addWidget(statusW);

    setActivePage(PAGE_CONNECTIONS);
}

// ── makeNavButton ─────────────────────────────────────────────────────

QPushButton *Sidebar::makeNavButton(const QString &label,
                                    const QString &icon,
                                    Page page)
{
    auto *btn = new QPushButton(this);
    btn->setFixedHeight(40);
    btn->setCursor(Qt::PointingHandCursor);
    btn->setProperty("label", label);
    btn->setProperty("icon", icon);

    // Show "  icon  label" in expanded mode
    btn->setText(QString("  %1  %2").arg(icon, label));
    btn->setStyleSheet(STYLE_INACTIVE);

    connect(btn, &QPushButton::clicked, this, [this, page]()
            {
        setActivePage(page);
        emit pageRequested(page); });
    return btn;
}

// ── setActive ─────────────────────────────────────────────────────────

void Sidebar::setActive(QPushButton *btn, bool active)
{
    btn->setStyleSheet(active
                           ? (m_collapsed ? STYLE_ACTIVE_ICON : STYLE_ACTIVE)
                           : (m_collapsed ? STYLE_INACTIVE_ICON : STYLE_INACTIVE));
}

// ── setActivePage ─────────────────────────────────────────────────────

void Sidebar::setActivePage(Page page)
{
    m_activePage = page;
    setActive(m_btnConnections, page == PAGE_CONNECTIONS);
    setActive(m_btnProcesses, page == PAGE_PROCESSES);
    setActive(m_btnRouteMap, page == PAGE_ROUTEMAP);
    setActive(m_btnDns, page == PAGE_DNS);
    setActive(m_btnAnomalies, page == PAGE_ANOMALIES);
    setActive(m_btnLoadBalancer, page == PAGE_LOADBALANCER);
    setActive(m_btnHistory, page == PAGE_HISTORY);
    setActive(m_btnCost, page == PAGE_COST);
    setActive(m_btnTimeline, page == PAGE_TIMELINE);
    setActive(m_btnDnsLeak, page == PAGE_DNSLEAK);
    setActive(m_btnBgp, page == PAGE_BGP);
    setActive(m_btnNetworkPerf, page == PAGE_NETWORKPERF);
    setActive(m_btnThreatMap, page == PAGE_THREATMAP);
    setActive(m_btnFirewall, page == PAGE_FIREWALL);
    setActive(m_btnTrust, page == PAGE_TRUST);
}

// ── toggleCollapse ────────────────────────────────────────────────────

void Sidebar::toggleCollapse()
{
    m_collapsed = !m_collapsed;
    applyCollapsed(m_collapsed);
}

void Sidebar::applyCollapsed(bool collapsed)
{
    auto *anim = new QPropertyAnimation(this, "minimumWidth");
    anim->setDuration(160);
    anim->setStartValue(width());
    anim->setEndValue(collapsed ? COLLAPSED_W : EXPANDED_W);
    anim->start(QAbstractAnimation::DeleteWhenStopped);

    auto *anim2 = new QPropertyAnimation(this, "maximumWidth");
    anim2->setDuration(160);
    anim2->setStartValue(width());
    anim2->setEndValue(collapsed ? COLLAPSED_W : EXPANDED_W);
    anim2->start(QAbstractAnimation::DeleteWhenStopped);

    m_titleLabel->setVisible(!collapsed);
    m_subLabel->setVisible(!collapsed);
    m_liveLabel->setVisible(!collapsed);
    m_btnCollapse->setText(collapsed ? "▶" : "◀");
    m_anomalyBadge->setVisible(!collapsed && !m_anomalyBadge->text().isEmpty());

    struct BtnInfo
    {
        QPushButton *btn;
        const char *label;
        const char *icon;
        Page page;
    } buttons[] = {
        {m_btnConnections, "Connections", ICONS[0], PAGE_CONNECTIONS},
        {m_btnProcesses, "Processes", ICONS[1], PAGE_PROCESSES},
        {m_btnRouteMap, "Route Map", ICONS[2], PAGE_ROUTEMAP},
        {m_btnLoadBalancer, "Bandwidth Load", ICONS[5], PAGE_LOADBALANCER},
        {m_btnTimeline, "Timeline", ICONS[8], PAGE_TIMELINE},
        {m_btnHistory, "History", ICONS[6], PAGE_HISTORY},
        {m_btnNetworkPerf, "Net Perf", ICONS[11], PAGE_NETWORKPERF},
        {m_btnDns, "DNS Map", ICONS[3], PAGE_DNS},
        {m_btnAnomalies, "Anomalies", ICONS[4], PAGE_ANOMALIES},
        {m_btnDnsLeak, "DNS Leaks", ICONS[9], PAGE_DNSLEAK},
        {m_btnBgp, "BGP Monitor", ICONS[10], PAGE_BGP},
        {m_btnThreatMap, "Threat Map", ICONS[12], PAGE_THREATMAP},
        {m_btnFirewall, "Firewall", ICONS[13], PAGE_FIREWALL},
        {m_btnTrust, "Trust", ICONS[14], PAGE_TRUST},
        {m_btnCost, "Data Cost", ICONS[7], PAGE_COST},
    };

    for (auto &b : buttons)
    {
        if (collapsed)
            b.btn->setText(QString("  %1").arg(b.icon));
        else
            b.btn->setText(QString("  %1  %2").arg(b.icon, b.label));
        setActive(b.btn, m_activePage == b.page);
    }

    for (auto *lbl : findChildren<QLabel *>("SectionTitle"))
        lbl->setVisible(!collapsed);
}

// ── setAnomalyCount ───────────────────────────────────────────────────

void Sidebar::setAnomalyCount(int count)
{
    if (count <= 0)
    {
        m_anomalyBadge->hide();
    }
    else
    {
        m_anomalyBadge->setText(QString::number(qMin(count, 99)));
        if (!m_collapsed)
            m_anomalyBadge->show();
    }
}