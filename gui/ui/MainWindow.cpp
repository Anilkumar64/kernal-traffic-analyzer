#include "MainWindow.h"
#include "Style.h"
#include <QApplication>
#include <QHBoxLayout>
#include <QVBoxLayout>
#include <QFrame>
#include <QStatusBar>
#include <QDateTime>

MainWindow::MainWindow(QWidget *parent) : QMainWindow(parent)
{
    setWindowTitle("Kernel Traffic Analyzer  v6.0");
    resize(1400, 860);
    setMinimumSize(1100, 700);

    qApp->setStyleSheet(Style::globalStyleSheet());

    buildLayout();

    m_statusLabel = new QLabel("Waiting for kernel module...", this);
    m_statusLabel->setStyleSheet(
        "color:#8b949e;font-size:11px;padding:0 8px;font-family:'Ubuntu Mono';");
    statusBar()->addPermanentWidget(m_statusLabel);
    statusBar()->setSizeGripEnabled(false);

    m_timer = new QTimer(this);
    connect(m_timer, &QTimer::timeout, this, &MainWindow::refresh);
    m_timer->start(m_refreshMs);

    refresh();
}

void MainWindow::buildLayout()
{
    auto *central = new QWidget(this);
    setCentralWidget(central);

    auto *root = new QHBoxLayout(central);
    root->setContentsMargins(0, 0, 0, 0);
    root->setSpacing(0);

    // Sidebar
    m_sidebar = new Sidebar(central);
    connect(m_sidebar, &Sidebar::pageRequested,
            this, &MainWindow::onPageRequested);
    root->addWidget(m_sidebar);

    // Divider
    auto *div = new QFrame(central);
    div->setFrameShape(QFrame::VLine);
    div->setStyleSheet("background:#30363d;max-width:1px;");
    root->addWidget(div);

    // Page stack
    m_stack = new QStackedWidget(central);
    root->addWidget(m_stack, 1);

    m_connectionsTab = new ConnectionsTab(m_stack);
    m_processesTab   = new ProcessesTab(m_stack);
    m_routeMap       = new RouteMapWidget(m_stack);
    m_dnsTab         = new DnsTab(m_stack);
    m_anomalyTab     = new AnomalyTab(m_stack);

    m_stack->addWidget(m_connectionsTab); // index 0 — PAGE_CONNECTIONS
    m_stack->addWidget(m_processesTab);   // index 1 — PAGE_PROCESSES
    m_stack->addWidget(m_routeMap);       // index 2 — PAGE_ROUTEMAP
    m_stack->addWidget(m_dnsTab);         // index 3 — PAGE_DNS
    m_stack->addWidget(m_anomalyTab);     // index 4 — PAGE_ANOMALIES

    m_stack->setCurrentIndex(0);
}

void MainWindow::refresh()
{
    ProcSnapshot snap = ProcReader::readAll();
    applySnapshot(snap);
}

void MainWindow::applySnapshot(const ProcSnapshot &snap)
{
    m_connectionsTab->updateData(snap.connections);
    m_processesTab->updateData(snap.processes);
    m_routeMap->updateRoutes(snap.routes, snap.connections);
    m_dnsTab->updateData(snap.dnsMap);
    m_anomalyTab->updateData(snap.anomalies);
    m_sidebar->setAnomalyCount(snap.anomalyCount());

    int active = 0;
    for (const auto &e : snap.connections)
        if (e.isActive()) active++;

    m_statusLabel->setText(
        QString("%1 connections  |  %2 active  |  %3 processes  |  "
                "%4 anomalies  |  %5")
            .arg(snap.connections.size())
            .arg(active)
            .arg(snap.processes.size())
            .arg(snap.anomalyCount())
            .arg(QDateTime::currentDateTime().toString("hh:mm:ss")));
}

void MainWindow::onPageRequested(Sidebar::Page page)
{
    m_stack->setCurrentIndex(static_cast<int>(page));
}
