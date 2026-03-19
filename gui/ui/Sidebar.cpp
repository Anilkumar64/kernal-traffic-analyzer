#include "Sidebar.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QFrame>
#include <QPropertyAnimation>

static const QString STYLE_ACTIVE =
    "QPushButton { background:#1f3349; color:#58a6ff; border:none; "
    "border-left:2px solid #1f6feb; text-align:left; padding:10px 14px; "
    "font-size:13px; font-family:'Ubuntu Mono'; }";

static const QString STYLE_INACTIVE =
    "QPushButton { background:transparent; color:#8b949e; border:none; "
    "text-align:left; padding:10px 14px; font-size:13px; "
    "font-family:'Ubuntu Mono'; }"
    "QPushButton:hover { background:#22272e; color:#e6edf3; }";

static const QString STYLE_ACTIVE_ICON =
    "QPushButton { background:#1f3349; color:#58a6ff; border:none; "
    "border-left:2px solid #1f6feb; text-align:center; padding:10px 4px; "
    "font-size:16px; font-family:'Ubuntu Mono'; }";

static const QString STYLE_INACTIVE_ICON =
    "QPushButton { background:transparent; color:#8b949e; border:none; "
    "text-align:center; padding:10px 4px; font-size:16px; "
    "font-family:'Ubuntu Mono'; }"
    "QPushButton:hover { background:#22272e; color:#e6edf3; }";

Sidebar::Sidebar(QWidget *parent) : QWidget(parent)
{
    setObjectName("Sidebar");
    setFixedWidth(EXPANDED_W);

    auto *layout = new QVBoxLayout(this);
    layout->setContentsMargins(0, 0, 0, 0);
    layout->setSpacing(0);

    // Logo
    m_logoWidget = new QWidget(this);
    m_logoWidget->setObjectName("SidebarLogo");
    m_logoWidget->setFixedHeight(64);
    auto *ll = new QHBoxLayout(m_logoWidget);
    ll->setContentsMargins(12, 0, 8, 0);

    auto *dot = new QLabel(m_logoWidget);
    dot->setFixedSize(10, 10);
    dot->setStyleSheet("background:#1f6feb;border-radius:5px;");

    auto *textCol = new QVBoxLayout();
    textCol->setSpacing(2);
    m_titleLabel = new QLabel("KTA", m_logoWidget);
    m_titleLabel->setStyleSheet(
        "color:#e6edf3;font-size:15px;font-weight:600;letter-spacing:2px;");
    m_subLabel = new QLabel("kernel traffic analyzer", m_logoWidget);
    m_subLabel->setStyleSheet("color:#484f58;font-size:9px;");
    textCol->addWidget(m_titleLabel);
    textCol->addWidget(m_subLabel);

    m_btnCollapse = new QPushButton("◀", m_logoWidget);
    m_btnCollapse->setObjectName("CollapseBtn");
    m_btnCollapse->setFixedSize(24, 24);
    m_btnCollapse->setStyleSheet(
        "QPushButton{background:transparent;border:1px solid #30363d;"
        "border-radius:4px;color:#484f58;font-size:11px;}"
        "QPushButton:hover{color:#e6edf3;border-color:#444c56;}");
    connect(m_btnCollapse, &QPushButton::clicked, this, &Sidebar::toggleCollapse);

    ll->addWidget(dot);
    ll->addSpacing(8);
    ll->addLayout(textCol);
    ll->addStretch();
    ll->addWidget(m_btnCollapse);
    layout->addWidget(m_logoWidget);

    auto mkDiv = [&]() {
        auto *f = new QFrame(this);
        f->setFrameShape(QFrame::HLine);
        f->setStyleSheet("background:#30363d;max-height:1px;");
        return f;
    };
    auto mkSec = [&](const QString &t) {
        auto *l = new QLabel(t, this);
        l->setObjectName("SectionTitle");
        return l;
    };

    layout->addWidget(mkDiv());
    layout->addWidget(mkSec("MONITOR"));

    m_btnConnections = makeNavButton("Connections", "⬡", PAGE_CONNECTIONS);
    m_btnProcesses   = makeNavButton("Processes",   "⬡", PAGE_PROCESSES);
    m_btnRouteMap    = makeNavButton("Route Map",   "⬡", PAGE_ROUTEMAP);
    layout->addWidget(m_btnConnections);
    layout->addWidget(m_btnProcesses);
    layout->addWidget(m_btnRouteMap);

    layout->addWidget(mkSec("INTELLIGENCE"));

    m_btnDns       = makeNavButton("DNS Map",   "⬡", PAGE_DNS);
    m_btnAnomalies = makeNavButton("Anomalies", "⬡", PAGE_ANOMALIES);

    // Anomaly row with badge
    auto *aRow = new QWidget(this);
    auto *aLayout = new QHBoxLayout(aRow);
    aLayout->setContentsMargins(0, 0, 8, 0);
    aLayout->setSpacing(0);
    aLayout->addWidget(m_btnAnomalies);
    m_anomalyBadge = new QLabel(aRow);
    m_anomalyBadge->setFixedSize(20, 20);
    m_anomalyBadge->setAlignment(Qt::AlignCenter);
    m_anomalyBadge->setStyleSheet(
        "background:#2d1117;color:#f85149;border-radius:10px;"
        "font-size:10px;font-weight:600;");
    m_anomalyBadge->hide();
    aLayout->addWidget(m_anomalyBadge);

    layout->addWidget(m_btnDns);
    layout->addWidget(aRow);
    layout->addStretch();
    layout->addWidget(mkDiv());

    // Live status
    auto *statusW = new QWidget(this);
    statusW->setFixedHeight(44);
    auto *sl = new QHBoxLayout(statusW);
    sl->setContentsMargins(14, 0, 14, 0);
    auto *liveDot = new QLabel(statusW);
    liveDot->setFixedSize(8, 8);
    liveDot->setStyleSheet("background:#3fb950;border-radius:4px;");
    m_liveLabel = new QLabel("Live  |  v6.0", statusW);
    m_liveLabel->setStyleSheet("color:#3fb950;font-size:10px;");
    sl->addWidget(liveDot);
    sl->addSpacing(8);
    sl->addWidget(m_liveLabel);
    sl->addStretch();
    layout->addWidget(statusW);

    // Set initial active
    setActive(m_btnConnections, true);
    for (auto *b : {m_btnProcesses, m_btnRouteMap, m_btnDns, m_btnAnomalies})
        setActive(b, false);
}

QPushButton *Sidebar::makeNavButton(const QString &label, const QString &/*icon*/, Page page)
{
    auto *btn = new QPushButton(label, this);
    btn->setFixedHeight(40);
    btn->setCursor(Qt::PointingHandCursor);
    btn->setStyleSheet(STYLE_INACTIVE);
    // Store label for collapse/expand
    btn->setProperty("label", label);
    connect(btn, &QPushButton::clicked, this, [this, page]() {
        setActivePage(page);
        emit pageRequested(page);
    });
    return btn;
}

void Sidebar::setActive(QPushButton *btn, bool active)
{
    btn->setStyleSheet(active ?
        (m_collapsed ? STYLE_ACTIVE_ICON : STYLE_ACTIVE) :
        (m_collapsed ? STYLE_INACTIVE_ICON : STYLE_INACTIVE));
}

void Sidebar::setActivePage(Page page)
{
    m_activePage = page;
    setActive(m_btnConnections, page == PAGE_CONNECTIONS);
    setActive(m_btnProcesses,   page == PAGE_PROCESSES);
    setActive(m_btnRouteMap,    page == PAGE_ROUTEMAP);
    setActive(m_btnDns,         page == PAGE_DNS);
    setActive(m_btnAnomalies,   page == PAGE_ANOMALIES);
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

    // Show/hide text
    m_titleLabel->setVisible(!collapsed);
    m_subLabel->setVisible(!collapsed);
    m_liveLabel->setVisible(!collapsed);
    m_anomalyBadge->setVisible(!collapsed && m_anomalyBadge->text().size() > 0);

    // Flip arrow
    m_btnCollapse->setText(collapsed ? "▶" : "◀");

    // Update button text (icon only when collapsed)
    auto updateBtn = [&](QPushButton *btn, const QString &label, bool active) {
        btn->setText(collapsed ? "●" : label);
        setActive(btn, active);
    };
    updateBtn(m_btnConnections, "Connections", m_activePage == PAGE_CONNECTIONS);
    updateBtn(m_btnProcesses,   "Processes",   m_activePage == PAGE_PROCESSES);
    updateBtn(m_btnRouteMap,    "Route Map",   m_activePage == PAGE_ROUTEMAP);
    updateBtn(m_btnDns,         "DNS Map",     m_activePage == PAGE_DNS);
    updateBtn(m_btnAnomalies,   "Anomalies",   m_activePage == PAGE_ANOMALIES);

    // Update section labels
    for (auto *lbl : findChildren<QLabel*>("SectionTitle"))
        lbl->setVisible(!collapsed);
}

void Sidebar::setAnomalyCount(int count)
{
    if (count <= 0) {
        m_anomalyBadge->hide();
    } else {
        m_anomalyBadge->setText(QString::number(qMin(count, 99)));
        if (!m_collapsed) m_anomalyBadge->show();
    }
}
