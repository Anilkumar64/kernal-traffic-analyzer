#include "Sidebar.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QFrame>
#include <QPropertyAnimation>

static const QString STYLE_ACTIVE =
    "QPushButton { background:#e0ecff; color:#6366f1; border:none; "
    "border-left:3px solid #6366f1; text-align:left; padding:10px 14px; "
    "font-size:13px; font-family:'Ubuntu Mono'; font-weight:600; }";

static const QString STYLE_INACTIVE =
    "QPushButton { background:transparent; color:#5c6b7f; border:none; "
    "text-align:left; padding:10px 14px; font-size:13px; "
    "font-family:'Ubuntu Mono'; }"
    "QPushButton:hover { background:#eef1f6; color:#1e2a3a; }";

static const QString STYLE_ACTIVE_ICON =
    "QPushButton { background:#e0ecff; color:#6366f1; border:none; "
    "border-left:3px solid #6366f1; text-align:center; padding:10px 4px; "
    "font-size:16px; font-family:'Ubuntu Mono'; font-weight:600; }";

static const QString STYLE_INACTIVE_ICON =
    "QPushButton { background:transparent; color:#5c6b7f; border:none; "
    "text-align:center; padding:10px 4px; font-size:16px; "
    "font-family:'Ubuntu Mono'; }"
    "QPushButton:hover { background:#eef1f6; color:#1e2a3a; }";

Sidebar::Sidebar(QWidget *parent) : QWidget(parent)
{
    setObjectName("Sidebar");
    setFixedWidth(EXPANDED_W);

    auto *layout = new QVBoxLayout(this);
    layout->setContentsMargins(0, 0, 0, 0);
    layout->setSpacing(0);

    // ── Logo ─────────────────────────────────────────────────────
    m_logoWidget = new QWidget(this);
    m_logoWidget->setObjectName("SidebarLogo");
    m_logoWidget->setFixedHeight(64);
    auto *ll = new QHBoxLayout(m_logoWidget);
    ll->setContentsMargins(12, 0, 8, 0);

    auto *dot = new QLabel(m_logoWidget);
    dot->setFixedSize(10, 10);
    dot->setStyleSheet("background:#6366f1;border-radius:5px;");

    auto *textCol = new QVBoxLayout();
    textCol->setSpacing(2);
    m_titleLabel = new QLabel("KTA", m_logoWidget);
    m_titleLabel->setStyleSheet(
        "color:#1e2a3a;font-size:15px;font-weight:600;letter-spacing:2px;");
    m_subLabel = new QLabel("kernel traffic analyzer", m_logoWidget);
    m_subLabel->setStyleSheet("color:#9ba8b6;font-size:9px;");
    textCol->addWidget(m_titleLabel);
    textCol->addWidget(m_subLabel);

    m_btnCollapse = new QPushButton("◀", m_logoWidget);
    m_btnCollapse->setObjectName("CollapseBtn");
    m_btnCollapse->setFixedSize(24, 24);
    m_btnCollapse->setStyleSheet(
        "QPushButton{background:transparent;border:1px solid #d0d7e0;"
        "border-radius:4px;color:#9ba8b6;font-size:11px;}"
        "QPushButton:hover{color:#1e2a3a;border-color:#b8c4d0;}");
    connect(m_btnCollapse, &QPushButton::clicked, this, &Sidebar::toggleCollapse);

    ll->addWidget(dot);
    ll->addSpacing(8);
    ll->addLayout(textCol);
    ll->addStretch();
    ll->addWidget(m_btnCollapse);
    layout->addWidget(m_logoWidget);

    auto mkDiv = [&]()
    {
        auto *f = new QFrame(this);
        f->setFrameShape(QFrame::HLine);
        f->setStyleSheet("background:#e4e8ee;max-height:1px;");
        return f;
    };
    auto mkSec = [&](const QString &t)
    {
        auto *l = new QLabel(t, this);
        l->setObjectName("SectionTitle");
        l->setStyleSheet(
            "color:#9ba8b6;font-size:9px;font-weight:700;"
            "letter-spacing:1.5px;padding:8px 14px 4px 14px;");
        return l;
    };

    // ── MONITOR section ───────────────────────────────────────────
    layout->addWidget(mkDiv());
    layout->addWidget(mkSec("MONITOR"));

    m_btnConnections = makeNavButton("Connections", "⬡", PAGE_CONNECTIONS);
    m_btnProcesses = makeNavButton("Processes", "⬡", PAGE_PROCESSES);
    m_btnRouteMap = makeNavButton("Route Map", "⬡", PAGE_ROUTEMAP);
    m_btnLoadBalancer = makeNavButton("Bandwidth Load", "⬡", PAGE_LOADBALANCER);
    m_btnTimeline = makeNavButton("Timeline", "⬡", PAGE_TIMELINE);
    m_btnHistory = makeNavButton("History", "⬡", PAGE_HISTORY);
    m_btnNetworkPerf = makeNavButton("Net Perf", "⬡", PAGE_NETWORKPERF);

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

    m_btnDns = makeNavButton("DNS Map", "⬡", PAGE_DNS);
    m_btnDnsLeak = makeNavButton("DNS Leaks", "⬡", PAGE_DNSLEAK);
    m_btnBgp = makeNavButton("BGP Monitor", "⬡", PAGE_BGP);
    m_btnThreatMap = makeNavButton("Threat Map", "⬡", PAGE_THREATMAP);

    // Anomaly row with badge
    m_btnAnomalies = makeNavButton("Anomalies", "⬡", PAGE_ANOMALIES);
    auto *aRow = new QWidget(this);
    auto *aLayout = new QHBoxLayout(aRow);
    aLayout->setContentsMargins(0, 0, 8, 0);
    aLayout->setSpacing(0);
    aLayout->addWidget(m_btnAnomalies);
    m_anomalyBadge = new QLabel(aRow);
    m_anomalyBadge->setFixedSize(20, 20);
    m_anomalyBadge->setAlignment(Qt::AlignCenter);
    m_anomalyBadge->setStyleSheet(
        "background:#fef2f2;color:#ef4444;border-radius:10px;"
        "font-size:10px;font-weight:600;");
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

    m_btnFirewall = makeNavButton("Firewall", "⬡", PAGE_FIREWALL);
    m_btnTrust = makeNavButton("Trust", "⬡", PAGE_TRUST);
    m_btnCost = makeNavButton("Data Cost", "⬡", PAGE_COST);

    layout->addWidget(m_btnFirewall);
    layout->addWidget(m_btnTrust);
    layout->addWidget(m_btnCost);

    layout->addStretch();
    layout->addWidget(mkDiv());

    // ── Live status ───────────────────────────────────────────────
    auto *statusW = new QWidget(this);
    statusW->setFixedHeight(44);
    auto *sl = new QHBoxLayout(statusW);
    sl->setContentsMargins(14, 0, 14, 0);
    auto *liveDot = new QLabel(statusW);
    liveDot->setFixedSize(8, 8);
    liveDot->setStyleSheet("background:#10b981;border-radius:4px;");
    m_liveLabel = new QLabel("Live  |  v6.0", statusW);
    m_liveLabel->setStyleSheet("color:#10b981;font-size:10px;");
    sl->addWidget(liveDot);
    sl->addSpacing(8);
    sl->addWidget(m_liveLabel);
    sl->addStretch();
    layout->addWidget(statusW);

    setActivePage(PAGE_CONNECTIONS);
}

QPushButton *Sidebar::makeNavButton(const QString &label,
                                    const QString & /*icon*/,
                                    Page page)
{
    auto *btn = new QPushButton(label, this);
    btn->setFixedHeight(38);
    btn->setCursor(Qt::PointingHandCursor);
    btn->setProperty("label", label);
    btn->setStyleSheet(STYLE_INACTIVE);
    connect(btn, &QPushButton::clicked, this, [this, page]()
            {
        setActivePage(page);
        emit pageRequested(page); });
    return btn;
}

void Sidebar::setActive(QPushButton *btn, bool active)
{
    btn->setStyleSheet(active
                           ? (m_collapsed ? STYLE_ACTIVE_ICON : STYLE_ACTIVE)
                           : (m_collapsed ? STYLE_INACTIVE_ICON : STYLE_INACTIVE));
}

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

void Sidebar::toggleCollapse()
{
    m_collapsed = !m_collapsed;
    applyCollapsed(m_collapsed);
}

void Sidebar::applyCollapsed(bool collapsed)
{
    auto *anim = new QPropertyAnimation(this, "minimumWidth");
    anim->setDuration(180);
    anim->setStartValue(width());
    anim->setEndValue(collapsed ? COLLAPSED_W : EXPANDED_W);
    anim->start(QAbstractAnimation::DeleteWhenStopped);

    auto *anim2 = new QPropertyAnimation(this, "maximumWidth");
    anim2->setDuration(180);
    anim2->setStartValue(width());
    anim2->setEndValue(collapsed ? COLLAPSED_W : EXPANDED_W);
    anim2->start(QAbstractAnimation::DeleteWhenStopped);

    m_titleLabel->setVisible(!collapsed);
    m_subLabel->setVisible(!collapsed);
    m_liveLabel->setVisible(!collapsed);
    m_anomalyBadge->setVisible(!collapsed && !m_anomalyBadge->text().isEmpty());
    m_btnCollapse->setText(collapsed ? "▶" : "◀");

    struct
    {
        QPushButton *btn;
        const char *label;
        Page page;
    } buttons[] = {
        {m_btnConnections, "Connections", PAGE_CONNECTIONS},
        {m_btnProcesses, "Processes", PAGE_PROCESSES},
        {m_btnRouteMap, "Route Map", PAGE_ROUTEMAP},
        {m_btnLoadBalancer, "Bandwidth Load", PAGE_LOADBALANCER},
        {m_btnTimeline, "Timeline", PAGE_TIMELINE},
        {m_btnHistory, "History", PAGE_HISTORY},
        {m_btnNetworkPerf, "Net Perf", PAGE_NETWORKPERF},
        {m_btnDns, "DNS Map", PAGE_DNS},
        {m_btnAnomalies, "Anomalies", PAGE_ANOMALIES},
        {m_btnDnsLeak, "DNS Leaks", PAGE_DNSLEAK},
        {m_btnBgp, "BGP Monitor", PAGE_BGP},
        {m_btnThreatMap, "Threat Map", PAGE_THREATMAP},
        {m_btnFirewall, "Firewall", PAGE_FIREWALL},
        {m_btnTrust, "Trust", PAGE_TRUST},
        {m_btnCost, "Data Cost", PAGE_COST},
    };

    for (auto &b : buttons)
    {
        b.btn->setText(collapsed ? "●" : b.label);
        setActive(b.btn, m_activePage == b.page);
    }

    for (auto *lbl : findChildren<QLabel *>("SectionTitle"))
        lbl->setVisible(!collapsed);
}

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