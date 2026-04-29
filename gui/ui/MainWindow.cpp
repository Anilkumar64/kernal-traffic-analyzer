#include "MainWindow.h"
#include "AnomalyTab.h"
#include "ConnectionsTab.h"
#include "DnsTab.h"
#include "HistoryTab.h"
#include "NetworkPerfTab.h"
#include "ProcessesTab.h"
#include "RoutesTab.h"
#include "Sidebar.h"
#include "../core/Exporter.h"
#include "../core/HistoryDB.h"
#include <QDateTime>
#include <QFileDialog>
#include <QHBoxLayout>
#include <QMenuBar>
#include <QMessageBox>
#include <QStackedWidget>
#include <QStatusBar>
#include <QTimer>

MainWindow::MainWindow(QWidget *parent) : QMainWindow(parent)
{
    setWindowTitle("Kernel Traffic Analyzer");
    resize(1180, 760);
    auto *file = menuBar()->addMenu("File");
    auto *exportMenu = file->addMenu("Export");
    exportMenu->addAction("JSON", this, &MainWindow::exportJson);
    exportMenu->addAction("CSV", this, &MainWindow::exportCsv);
    menuBar()->addMenu("Help")->addAction("About", this, [this] {
        QMessageBox::about(this, "About", "Kernel Traffic Analyzer\nLinux process-level network observability.");
    });

    auto *central = new QWidget(this);
    auto *layout = new QHBoxLayout(central);
    layout->setContentsMargins(0, 0, 0, 0);
    m_sidebar = new Sidebar(central);
    m_stack = new QStackedWidget(central);
    m_connectionsTab = new ConnectionsTab(m_stack);
    m_processesTab = new ProcessesTab(m_stack);
    m_dnsTab = new DnsTab(m_stack);
    m_anomalyTab = new AnomalyTab(m_stack);
    m_routesTab = new RoutesTab(m_stack);
    m_historyTab = new HistoryTab(m_stack);
    m_networkPerfTab = new NetworkPerfTab(m_stack);
    for (auto *w : {static_cast<QWidget *>(m_connectionsTab), static_cast<QWidget *>(m_processesTab), static_cast<QWidget *>(m_dnsTab),
                    static_cast<QWidget *>(m_anomalyTab), static_cast<QWidget *>(m_routesTab), static_cast<QWidget *>(m_historyTab),
                    static_cast<QWidget *>(m_networkPerfTab)}) {
        m_stack->addWidget(w);
    }
    layout->addWidget(m_sidebar);
    layout->addWidget(m_stack, 1);
    setCentralWidget(central);
    connect(m_sidebar, &Sidebar::currentChanged, this, [this](int index) {
        m_sidebar->setCurrentIndex(index);
        m_stack->setCurrentIndex(index);
        if (m_stack->currentWidget() == m_historyTab) m_historyTab->refresh();
    });

    HistoryDB::instance().open();
    m_timer = new QTimer(this);
    connect(m_timer, &QTimer::timeout, this, &MainWindow::refresh);
    m_timer->start(1000);
    m_historyTimer = new QTimer(this);
    connect(m_historyTimer, &QTimer::timeout, this, &MainWindow::writeHistory);
    m_historyTimer->start(60000);
    refresh();
}

void MainWindow::refresh()
{
    m_snap = ProcReader::readAll();
    m_connectionsTab->updateData(m_snap.connections);
    m_processesTab->updateData(m_snap.processes, m_snap.connections);
    m_dnsTab->updateData(m_snap.dnsMap);
    m_anomalyTab->updateData(m_snap.anomalies);
    m_routesTab->updateData(QVector<RouteEntry>(m_snap.routes.begin(), m_snap.routes.end()));
    m_networkPerfTab->updateData(m_snap);
    m_sidebar->setAnomalyCount(m_snap.anomalyCount());
    if (m_stack->currentWidget() == m_historyTab) m_historyTab->refresh();
    updateStatusBar();
}

void MainWindow::writeHistory()
{
    QVector<BwSample> samples;
    const auto now = QDateTime::currentSecsSinceEpoch();
    for (const auto &p : m_snap.processes)
        samples.append({now, p.pid, p.process, p.rateOutBps, p.rateInBps, quint64(p.bytesOut), quint64(p.bytesIn)});
    HistoryDB::instance().insertSamples(samples);
}

void MainWindow::updateStatusBar()
{
    const auto active = std::count_if(m_snap.connections.begin(), m_snap.connections.end(), [](const TrafficEntry &e) { return e.isActive(); });
    const auto text = m_snap.connections.isEmpty() && m_snap.processes.isEmpty()
        ? QString("Waiting for kernel module... | %1").arg(QTime::currentTime().toString("hh:mm:ss"))
        : QString("%1 connections | %2 active | %3 processes | %4")
              .arg(m_snap.connections.size()).arg(active).arg(m_snap.processes.size()).arg(QTime::currentTime().toString("hh:mm:ss"));
    statusBar()->showMessage(text);
}

void MainWindow::exportJson()
{
    const auto path = QFileDialog::getSaveFileName(this, "Export JSON", {}, "JSON (*.json)");
    if (!path.isEmpty() && !Exporter(this).exportJson(path, m_snap))
        QMessageBox::warning(this, "Export Failed", "Could not write the JSON export.");
}

void MainWindow::exportCsv()
{
    const auto path = QFileDialog::getSaveFileName(this, "Export CSV", {}, "CSV (*.csv)");
    if (!path.isEmpty() && !Exporter(this).exportCsv(path, m_snap.connections))
        QMessageBox::warning(this, "Export Failed", "Could not write the CSV export.");
}
