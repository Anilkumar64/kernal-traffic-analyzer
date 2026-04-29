/**
 * @file MainWindow.cpp
 * @brief Implementation of the Kernel Traffic Analyzer main window.
 * @details Wires the sidebar shell, live data refresh, history autosave, exports, status bar, and tab updates.
 * @author Kernel Traffic Analyzer Project
 * @license MIT
 */
#include "MainWindow.h"

#include "Exporter.h"
#include "Style.h"
#include "tabs/AnomalyTab.h"
#include "tabs/ConnectionsTab.h"
#include "tabs/DnsTab.h"
#include "tabs/HistoryTab.h"
#include "tabs/NetworkPerfTab.h"
#include "tabs/ProcessesTab.h"
#include "tabs/RoutesTab.h"

#include <QApplication>
#include <QButtonGroup>
#include <QDir>
#include <QFile>
#include <QGraphicsOpacityEffect>
#include <QHBoxLayout>
#include <QLabel>
#include <QMenuBar>
#include <QMessageBox>
#include <QStackedWidget>
#include <QStandardPaths>
#include <QStatusBar>
#include <QTimer>
#include <QToolButton>
#include <QVBoxLayout>

MainWindow::MainWindow(QWidget* parent)
    : QMainWindow(parent),
      proc_reader_(std::make_unique<ProcReader>()),
      history_db_(std::make_unique<HistoryDB>())
{
    setupUi();
    setupConnections();
    applyStylesheet();

    const QString dataDir = QStandardPaths::writableLocation(QStandardPaths::AppDataLocation);
    QDir().mkpath(dataDir);
    history_db_->open(QDir(dataDir).filePath("history.sqlite"));
    history_db_->pruneOld();
    tab_history_->setHistoryDB(history_db_.get());

    refresh_timer_->start(1000);
    autosave_timer_->start(5 * 60 * 1000);
    proc_reader_->requestRefresh();
}

MainWindow::~MainWindow()
{
    if (history_db_) {
        history_db_->endSession();
    }
}

void MainWindow::onDataReady(const ParsedData& data)
{
    current_data_ = data;
    tab_connections_->setConnections(data.connections);
    tab_processes_->setProcesses(data.processes, data.connections);
    tab_dns_->setDns(data.dns);
    tab_anomaly_->setAnomalies(data.anomalies);
    tab_routes_->setRoutes(data.routes);
    tab_perf_->updateFromData(data);
    updateStatusBar(data);
}

void MainWindow::onModuleNotLoaded()
{
    if (status_module_ != nullptr) {
        status_module_->setText("<span style='color:#f85149'>○ Module Not Loaded</span>");
    }
}

void MainWindow::onNavButtonClicked(int id)
{
    if (stack_ != nullptr && id >= 0 && id < stack_->count()) {
        stack_->setCurrentIndex(id);
    }
}

void MainWindow::onRefreshTimer()
{
    proc_reader_->requestRefresh();
}

void MainWindow::onAutoSave()
{
    if (history_db_) {
        history_db_->saveSnapshot(current_data_);
    }
}

void MainWindow::onBlinkTimer()
{
    blink_state_ = !blink_state_;
    if (anomaly_effect_ != nullptr) {
        anomaly_effect_->setOpacity(blink_state_ ? 0.30 : 1.0);
    }
}

void MainWindow::onExportJson()
{
    Exporter::exportJson(current_data_, this);
}

void MainWindow::onExportCsv()
{
    Exporter::exportCsv(current_data_, this);
}

void MainWindow::onAbout()
{
    QMessageBox::about(this, "About Kernel Traffic Analyzer",
        "Kernel Traffic Analyzer v1.0.0\nQt6 desktop interface for live kernel traffic telemetry.");
}

void MainWindow::onCriticalAnomalyActive(bool active)
{
    if (active) {
        if (!blink_timer_->isActive()) {
            blink_timer_->start(800);
        }
    } else {
        blink_timer_->stop();
        blink_state_ = false;
        if (anomaly_effect_ != nullptr) {
            anomaly_effect_->setOpacity(1.0);
        }
    }
}

void MainWindow::setupUi()
{
    setupMenuBar();
    auto* central = new QWidget(this);
    auto* layout = new QHBoxLayout(central);
    layout->setContentsMargins(0, 0, 0, 0);
    layout->setSpacing(0);
    setupSidebar();
    setupStack();
    layout->addWidget(sidebar_);
    layout->addWidget(stack_, 1);
    setCentralWidget(central);
    setupStatusBar();
}

void MainWindow::setupMenuBar()
{
    QMenu* fileMenu = menuBar()->addMenu("File");
    QAction* exportJson = fileMenu->addAction("Export JSON");
    QAction* exportCsv = fileMenu->addAction("Export CSV");
    fileMenu->addSeparator();
    QAction* quit = fileMenu->addAction("Quit");
    QMenu* helpMenu = menuBar()->addMenu("Help");
    QAction* about = helpMenu->addAction("About");
    connect(exportJson, &QAction::triggered, this, &MainWindow::onExportJson);
    connect(exportCsv, &QAction::triggered, this, &MainWindow::onExportCsv);
    connect(quit, &QAction::triggered, qApp, &QApplication::quit);
    connect(about, &QAction::triggered, this, &MainWindow::onAbout);
}

void MainWindow::setupSidebar()
{
    sidebar_ = new QWidget(this);
    sidebar_->setObjectName("Sidebar");
    sidebar_->setFixedWidth(64);
    auto* layout = new QVBoxLayout(sidebar_);
    layout->setContentsMargins(8, 12, 8, 12);
    layout->setSpacing(8);
    nav_group_ = new QButtonGroup(this);
    nav_group_->setExclusive(true);

    const QStringList names = {"Connections", "Processes", "DNS", "Anomalies", "Routes", "History", "Performance"};
    const QStringList icons = {
        ":/icons/connections.svg", ":/icons/processes.svg", ":/icons/dns.svg",
        ":/icons/anomaly.svg", ":/icons/routes.svg", ":/icons/history.svg", ":/icons/performance.svg"
    };
    for (int i = 0; i < names.size(); ++i) {
        auto* button = new QToolButton(sidebar_);
        button->setCheckable(true);
        button->setIcon(QIcon(icons.at(i)));
        button->setIconSize(QSize(28, 28));
        button->setToolTip(names.at(i));
        button->setFixedSize(48, 48);
        button->setAutoRaise(true);
        nav_buttons_[i] = button;
        nav_group_->addButton(button, i);
        layout->addWidget(button, 0, Qt::AlignHCenter);
    }
    nav_buttons_[0]->setChecked(true);
    anomaly_effect_ = new QGraphicsOpacityEffect(nav_buttons_[3]);
    anomaly_effect_->setOpacity(1.0);
    nav_buttons_[3]->setGraphicsEffect(anomaly_effect_);
    layout->addStretch(1);
    auto* version = new QLabel("v1.0.0", sidebar_);
    version->setAlignment(Qt::AlignCenter);
    version->setProperty("muted", true);
    layout->addWidget(version);
}

void MainWindow::setupStack()
{
    stack_ = new QStackedWidget(this);
    tab_connections_ = new ConnectionsTab(stack_);
    tab_processes_ = new ProcessesTab(stack_);
    tab_dns_ = new DnsTab(stack_);
    tab_anomaly_ = new AnomalyTab(stack_);
    tab_routes_ = new RoutesTab(stack_);
    tab_history_ = new HistoryTab(stack_);
    tab_perf_ = new NetworkPerfTab(stack_);
    stack_->addWidget(tab_connections_);
    stack_->addWidget(tab_processes_);
    stack_->addWidget(tab_dns_);
    stack_->addWidget(tab_anomaly_);
    stack_->addWidget(tab_routes_);
    stack_->addWidget(tab_history_);
    stack_->addWidget(tab_perf_);
}

void MainWindow::setupStatusBar()
{
    status_module_ = new QLabel(this);
    status_pkt_rate_ = new QLabel(this);
    status_bytes_ = new QLabel(this);
    status_uptime_ = new QLabel(this);
    statusBar()->addPermanentWidget(status_module_);
    statusBar()->addPermanentWidget(status_pkt_rate_);
    statusBar()->addPermanentWidget(status_bytes_);
    statusBar()->addPermanentWidget(status_uptime_);
    onModuleNotLoaded();
    status_pkt_rate_->setText("Packets: 0/s");
    status_bytes_->setText("Total: 0 B");
    status_uptime_->setText("Uptime: 00:00:00");
}

void MainWindow::setupConnections()
{
    refresh_timer_ = new QTimer(this);
    autosave_timer_ = new QTimer(this);
    blink_timer_ = new QTimer(this);
    connect(proc_reader_.get(), &ProcReader::dataReady, this, &MainWindow::onDataReady);
    connect(proc_reader_.get(), &ProcReader::moduleNotLoaded, this, &MainWindow::onModuleNotLoaded);
    connect(nav_group_, &QButtonGroup::idClicked, this, &MainWindow::onNavButtonClicked);
    connect(refresh_timer_, &QTimer::timeout, this, &MainWindow::onRefreshTimer);
    connect(autosave_timer_, &QTimer::timeout, this, &MainWindow::onAutoSave);
    connect(blink_timer_, &QTimer::timeout, this, &MainWindow::onBlinkTimer);
    connect(tab_anomaly_, &AnomalyTab::criticalAnomalyActive, this, &MainWindow::onCriticalAnomalyActive);
}

void MainWindow::applyStylesheet()
{
    QFile file(":/style/kta_dark.qss");
    if (file.open(QIODevice::ReadOnly | QIODevice::Text)) {
        qApp->setStyleSheet(QString::fromUtf8(file.readAll()));
    }
}

void MainWindow::updateStatusBar(const ParsedData& data)
{
    if (data.moduleLoaded) {
        status_module_->setText("<span style='color:#39d353'>● Module Loaded</span>");
    } else {
        onModuleNotLoaded();
    }
    status_pkt_rate_->setText(QString("Packets: %1/s").arg(data.stats.totalPackets));
    status_bytes_->setText(QString("Total: %1").arg(formatBytes(data.stats.totalBytes)));
    const quint64 sec = data.stats.uptimeSec;
    status_uptime_->setText(QString("Uptime: %1:%2:%3")
        .arg(sec / 3600, 2, 10, QLatin1Char('0'))
        .arg((sec / 60) % 60, 2, 10, QLatin1Char('0'))
        .arg(sec % 60, 2, 10, QLatin1Char('0')));
}
