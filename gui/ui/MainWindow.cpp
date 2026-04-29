#include "MainWindow.h"
#include "AnomalyTab.h"
#include "ConnectionsTab.h"
#include "DnsTab.h"
#include "HistoryTab.h"
#include "NetworkPerfTab.h"
#include "ProcessesTab.h"
#include "RoutesTab.h"
#include "Sidebar.h"
#include "StatusBar.h"
#include "Style.h"
#include "TitleBar.h"
#include "../core/Exporter.h"
#include "../core/HistoryDB.h"

#include <QFileDialog>
#include <QHBoxLayout>
#include <QMenuBar>
#include <QMessageBox>
#include <QStackedWidget>
#include <QTimer>
#include <QVBoxLayout>

MainWindow::MainWindow(QWidget *parent) : QMainWindow(parent)
{
    setWindowTitle("Kernel Traffic Analyzer");
    resize(1180, 760);

    auto *central = new QWidget(this);
    auto *root = new QVBoxLayout(central);
    root->setContentsMargins(0, 0, 0, 0);
    root->setSpacing(0);
    root->addWidget(new TitleBar(central));

    auto *menu = new QMenuBar(central);
    auto *file = menu->addMenu("File");
    file->addAction("Export JSON", this, &MainWindow::exportJson);
    file->addAction("Export CSV", this, &MainWindow::exportCsv);
    file->addSeparator();
    file->addAction("Quit", this, &QWidget::close);
    auto *help = menu->addMenu("Help");
    help->addAction("About", this, [this] {
        QMessageBox::about(this, "About", "Kernel Traffic Analyzer\nLinux process-level network observability.");
    });
    root->addWidget(menu);

    auto *body = new QWidget(central);
    auto *bodyLayout = new QHBoxLayout(body);
    bodyLayout->setContentsMargins(0, 0, 0, 0);
    bodyLayout->setSpacing(0);
    m_sidebar = new Sidebar(body);
    m_stack = new QStackedWidget(body);
    m_stack->setStyleSheet(QString("background:%1;").arg(Style::css(KtaColors::BgBase)));
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
    bodyLayout->addWidget(m_sidebar);
    bodyLayout->addWidget(m_stack, 1);
    root->addWidget(body, 1);

    m_status = new StatusBar(central);
    root->addWidget(m_status);
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
    const int current = m_stack->currentIndex();
    if (current == 0) m_connectionsTab->updateData(m_snap.connections);
    if (current == 1) m_processesTab->updateData(m_snap.processes, m_snap.connections);
    if (current == 2) m_dnsTab->updateData(m_snap.dnsMap);
    if (current == 3) m_anomalyTab->updateData(m_snap.anomalies);
    if (current == 4) m_routesTab->updateData(QVector<RouteEntry>(m_snap.routes.begin(), m_snap.routes.end()));
    if (current == 5) m_historyTab->refresh();
    if (current == 6) m_networkPerfTab->updateData(m_snap);
    m_sidebar->setAnomalyCount(m_snap.anomalyCount());
    m_sidebar->setModuleLoaded(!m_snap.connections.isEmpty() || !m_snap.processes.isEmpty() || !m_snap.dnsMap.isEmpty());
    m_status->updateSnapshot(m_snap);
}

void MainWindow::writeHistory()
{
    QVector<BwSample> samples;
    const auto now = QDateTime::currentSecsSinceEpoch();
    for (const auto &p : m_snap.processes)
        samples.append({now, p.pid, p.process, p.rateOutBps, p.rateInBps, quint64(p.bytesOut), quint64(p.bytesIn)});
    HistoryDB::instance().insertSamples(samples);
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
