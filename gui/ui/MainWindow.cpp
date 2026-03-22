#include "MainWindow.h"
#include "Style.h"
#include <QApplication>
#include <QHBoxLayout>
#include <QVBoxLayout>
#include <QFrame>
#include <QStatusBar>
#include <QDateTime>
#include <QMenuBar>
#include <QFileDialog>
#include <QMessageBox>
#include <QCloseEvent>

MainWindow::MainWindow(QWidget *parent) : QMainWindow(parent)
{
    setWindowTitle("Kernel Traffic Analyzer  v6.0");
    resize(1440, 900);
    setMinimumSize(1100, 700);
    qApp->setStyleSheet(Style::globalStyleSheet());

    // Init backend services
    HistoryDB::instance().open();
    m_bgpMonitor = new BgpMonitor(this);
    m_dnsLeakDetector = new DnsLeakDetector(this);
    m_exporter = new Exporter(this);

    buildLayout();
    buildMenuBar();

    // Alert popup
    m_alertPopup = new AlertPopup(this);

    // Tray icon
    if (QSystemTrayIcon::isSystemTrayAvailable())
        m_trayIcon = new TrayIcon(this);
    else
        m_trayIcon = nullptr;
    if (m_trayIcon)
        connect(m_trayIcon, &TrayIcon::showRequested,
                this, [this]()
                { show(); raise(); activateWindow(); });
    if (m_trayIcon)
        connect(m_trayIcon, &TrayIcon::quitRequested,
                qApp, &QApplication::quit);

    // Status bar
    m_statusLabel = new QLabel("Waiting for kernel module...", this);
    m_statusLabel->setStyleSheet(
        "color:#334455;font-size:12px;padding:0 8px;"
        "font-family:'Ubuntu Mono';");
    statusBar()->addPermanentWidget(m_statusLabel);
    statusBar()->setSizeGripEnabled(false);

    // Connect detectors
    m_dnsLeakTab->setDetector(m_dnsLeakDetector);
    m_bgpTab->setMonitor(m_bgpMonitor);

    connect(m_dnsLeakDetector, &DnsLeakDetector::leakDetected,
            this, [this](DnsLeakEvent ev)
            {
        if (ev.severity == LeakSeverity::Critical) {
            AnomalyEntry a;
            a.process = ev.process;
            a.pid     = ev.pid;
            a.anomaly = "DNS_LEAK";
            m_alertPopup->showAlert(a);
        } });

    connect(m_bgpMonitor, &BgpMonitor::bgpAlertDetected,
            this, [this](BgpAlert alert)
            { m_alertPopup->showBgpAlert(
                  alert.domain,
                  alert.expectedCountries.join("→"),
                  alert.actualCountries.join("→")); });

    // 1-second refresh
    m_timer = new QTimer(this);
    connect(m_timer, &QTimer::timeout, this, &MainWindow::refresh);
    m_timer->start(1000);

    // 60-second history sample
    m_historyTimer = new QTimer(this);
    connect(m_historyTimer, &QTimer::timeout,
            this, &MainWindow::onHistorySample);
    m_historyTimer->start(60000);

    m_dnsLeakDetector->start();
    m_bgpMonitor->start();

    refresh();
}

void MainWindow::buildLayout()
{
    auto *central = new QWidget(this);
    setCentralWidget(central);
    auto *root = new QHBoxLayout(central);
    root->setContentsMargins(0, 0, 0, 0);
    root->setSpacing(0);

    m_sidebar = new Sidebar(central);
    connect(m_sidebar, &Sidebar::pageRequested,
            this, &MainWindow::onPageRequested);
    root->addWidget(m_sidebar);

    auto *div = new QFrame(central);
    div->setFrameShape(QFrame::VLine);
    div->setStyleSheet("background:#1c2530;max-width:1px;");
    root->addWidget(div);

    m_stack = new QStackedWidget(central);
    root->addWidget(m_stack, 1);

    // Instantiate all tabs
    m_connectionsTab = new ConnectionsTab(m_stack);
    m_processesTab = new ProcessesTab(m_stack);
    m_routeMap = new RouteMapWidget(m_stack);
    m_dnsTab = new DnsTab(m_stack);
    m_anomalyTab = new AnomalyTab(m_stack);
    m_loadBalancerTab = new LoadBalancerTab(m_stack);
    m_historyTab = new HistoryTab(m_stack);
    m_costTab = new CostTab(m_stack);
    m_timelineTab = new TimelineTab(m_stack);
    m_dnsLeakTab = new DnsLeakTab(m_stack);
    m_bgpTab = new BgpTab(m_stack);
    m_networkPerfTab = new NetworkPerfTab(m_stack);
    m_threatMapTab = new ThreatMapTab(m_stack);
    m_firewallTab = new FirewallTab(m_stack);
    m_trustTab = new TrustTab(m_stack);

    // Add to stack — index MUST match Sidebar::Page enum exactly
    m_stack->addWidget(m_connectionsTab);  // 0  PAGE_CONNECTIONS
    m_stack->addWidget(m_processesTab);    // 1  PAGE_PROCESSES
    m_stack->addWidget(m_routeMap);        // 2  PAGE_ROUTEMAP
    m_stack->addWidget(m_dnsTab);          // 3  PAGE_DNS
    m_stack->addWidget(m_anomalyTab);      // 4  PAGE_ANOMALIES
    m_stack->addWidget(m_loadBalancerTab); // 5  PAGE_LOADBALANCER
    m_stack->addWidget(m_historyTab);      // 6  PAGE_HISTORY
    m_stack->addWidget(m_costTab);         // 7  PAGE_COST
    m_stack->addWidget(m_timelineTab);     // 8  PAGE_TIMELINE
    m_stack->addWidget(m_dnsLeakTab);      // 9  PAGE_DNSLEAK
    m_stack->addWidget(m_bgpTab);          // 10 PAGE_BGP
    m_stack->addWidget(m_networkPerfTab);  // 11 PAGE_NETWORKPERF
    m_stack->addWidget(m_threatMapTab);    // 12 PAGE_THREATMAP
    m_stack->addWidget(m_firewallTab);     // 13 PAGE_FIREWALL
    m_stack->addWidget(m_trustTab);        // 14 PAGE_TRUST
    m_stack->setCurrentIndex(0);

    // Process detail overlay
    m_processDetail = new ProcessDetailOverlay(central);
    m_processDetail->hide();
    connect(m_processDetail, &ProcessDetailOverlay::closed,
            [this]()
            { m_processDetail->hide(); });

    connect(m_loadBalancerTab, &LoadBalancerTab::processSelected,
            this, &MainWindow::onProcessSelected);
    connect(m_processesTab, &ProcessesTab::processClicked,
            this, [this](int, const QString &proc)
            { onProcessSelected(proc); });
}

void MainWindow::buildMenuBar()
{
    auto *fileMenu = menuBar()->addMenu("File");
    fileMenu->setStyleSheet(
        "QMenu{background:#131920;border:1px solid #253040;"
        "color:#dde8f5;font-family:'Ubuntu Mono';font-size:13px;}"
        "QMenu::item{padding:6px 20px;}"
        "QMenu::item:selected{background:#163050;color:#5aabff;}");

    auto *exportMenu = fileMenu->addMenu("Export");
    exportMenu->addAction("JSON Report...", this, &MainWindow::exportJson);
    exportMenu->addAction("CSV (Connections)...", this, &MainWindow::exportCsv);
    exportMenu->addAction("PDF Report...", this, &MainWindow::exportPdf);
    fileMenu->addSeparator();
    fileMenu->addAction("Quit", qApp, &QApplication::quit);
}

void MainWindow::refresh()
{
    m_lastSnap = ProcReader::readAll();
    applySnapshot(m_lastSnap);
}

void MainWindow::onHistorySample()
{
    QVector<BwSample> samples;
    for (const auto &p : m_lastSnap.processes)
    {
        BwSample s;
        s.ts = QDateTime::currentSecsSinceEpoch();
        s.pid = p.pid;
        s.process = p.process;
        s.outBps = p.rateOutBps;
        s.inBps = p.rateInBps;
        s.outBytes = p.bytesOut;
        s.inBytes = p.bytesIn;
        samples.append(s);
    }
    HistoryDB::instance().insertSamples(samples);
    m_historyTab->refresh();
    m_costTab->refresh();
}

void MainWindow::applySnapshot(const ProcSnapshot &snap)
{
    m_connectionsTab->updateData(snap.connections);
    m_processesTab->updateData(snap.processes);
    m_routeMap->updateRoutes(snap.routes, snap.connections);
    m_dnsTab->updateData(snap.dnsMap);
    m_anomalyTab->updateData(snap.anomalies);
    m_loadBalancerTab->updateData(snap.processes, snap.connections);
    m_timelineTab->updateData(snap.connections);
    m_threatMapTab->updateData(snap.connections);
    m_firewallTab->updateData(snap.connections, snap.processes);
    m_trustTab->updateData(snap.processes, snap.connections);
    m_sidebar->setAnomalyCount(snap.anomalyCount());

    // Feed BGP monitor
    for (auto it = snap.routes.begin(); it != snap.routes.end(); ++it)
    {
        QString domain = it.value().domain;
        if (domain.isEmpty() || domain == "-")
        {
            for (const auto &e : snap.connections)
                if (e.destIp == it.key() && !e.domain.isEmpty())
                    domain = e.domain;
        }
        m_bgpMonitor->updateRoute(it.key(), domain, it.value());
    }

    checkNewAnomalies(snap.anomalies);

    if (m_processDetail->isVisible())
    {
        m_processDetail->showProcess(
            m_processDetail->property("currentProcess").toString(),
            snap.processes, snap.connections,
            snap.dnsMap, snap.routes);
    }

    // Update tray
    quint32 totalRate = 0;
    int active = 0;
    for (const auto &e : snap.connections)
    {
        if (e.isActive())
        {
            active++;
            totalRate += e.rateInBps + e.rateOutBps;
        }
    }
    if (m_trayIcon)
        m_trayIcon->update(active, snap.anomalyCount(), totalRate);

    m_statusLabel->setText(
        QString("%1 connections  |  %2 active  |  "
                "%3 processes  |  %4 anomalies  |  %5")
            .arg(snap.connections.size())
            .arg(active)
            .arg(snap.processes.size())
            .arg(snap.anomalyCount())
            .arg(QDateTime::currentDateTime().toString("hh:mm:ss")));
}

void MainWindow::checkNewAnomalies(const QVector<AnomalyEntry> &anomalies)
{
    for (const auto &a : anomalies)
    {
        QString key = QString("%1:%2").arg(a.process, a.anomaly);
        if (!m_seenAnomalies.contains(key))
        {
            m_seenAnomalies.insert(key);
            m_alertPopup->showAlert(a);
            break;
        }
    }
    QSet<QString> current;
    for (const auto &a : anomalies)
        current.insert(QString("%1:%2").arg(a.process, a.anomaly));
    m_seenAnomalies &= current;
}

void MainWindow::onProcessSelected(const QString &process)
{
    m_processDetail->setProperty("currentProcess", process);
    m_processDetail->setGeometry(centralWidget()->geometry());
    m_processDetail->showProcess(
        process, m_lastSnap.processes,
        m_lastSnap.connections, m_lastSnap.dnsMap,
        m_lastSnap.routes);
}

void MainWindow::resizeEvent(QResizeEvent *e)
{
    QMainWindow::resizeEvent(e);
    if (m_processDetail && m_processDetail->isVisible())
        m_processDetail->setGeometry(centralWidget()->rect());
}

void MainWindow::closeEvent(QCloseEvent *e)
{
    hide();
    e->ignore();
    if (m_trayIcon)
        m_trayIcon->showMessage("KTA",
                                "KTA is running in the background",
                                QSystemTrayIcon::Information, 3000);
}

void MainWindow::onPageRequested(Sidebar::Page page)
{
    m_stack->setCurrentIndex(static_cast<int>(page));
}

void MainWindow::exportJson()
{
    QString path = QFileDialog::getSaveFileName(
        this, "Export JSON",
        QDir::homePath() + "/kta_report.json",
        "JSON Files (*.json)");
    if (path.isEmpty())
        return;
    if (m_exporter->exportJson(path, m_lastSnap))
        QMessageBox::information(this, "Export", "JSON report saved.");
    else
        QMessageBox::warning(this, "Export", "Failed to save JSON.");
}

void MainWindow::exportCsv()
{
    QString path = QFileDialog::getSaveFileName(
        this, "Export CSV",
        QDir::homePath() + "/kta_connections.csv",
        "CSV Files (*.csv)");
    if (path.isEmpty())
        return;
    if (m_exporter->exportCsv(path, m_lastSnap.connections))
        QMessageBox::information(this, "Export", "CSV saved.");
    else
        QMessageBox::warning(this, "Export", "Failed to save CSV.");
}

void MainWindow::exportPdf()
{
    QString path = QFileDialog::getSaveFileName(
        this, "Export PDF",
        QDir::homePath() + "/kta_report.pdf",
        "PDF Files (*.pdf)");
    if (path.isEmpty())
        return;
    if (m_exporter->exportPdf(path, m_lastSnap))
        QMessageBox::information(this, "Export", "PDF report saved.");
    else
        QMessageBox::warning(this, "Export", "Failed to save PDF.");
}