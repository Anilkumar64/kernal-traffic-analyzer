#pragma once
#include <QMainWindow>
#include <QStackedWidget>
#include <QTimer>
#include <QLabel>
#include <QSet>
#include "Sidebar.h"
#include "ConnectionsTab.h"
#include "ProcessesTab.h"
#include "RouteMapWidget.h"
#include "DnsTab.h"
#include "AnomalyTab.h"
#include "AlertPopup.h"
#include "LoadBalancerTab.h"
#include "ProcessDetailOverlay.h"
#include "HistoryTab.h"
#include "CostTab.h"
#include "TimelineTab.h"
#include "DnsLeakTab.h"
#include "BgpTab.h"
#include "TrayIcon.h"
#include "NetworkPerfTab.h"
#include "ThreatMapTab.h"
#include "FireWallTab.h"
#include "TrustTab.h"
#include "../core/ProcReader.h"
#include "../core/HistoryDB.h"
#include "../core/BgpMonitor.h"
#include "../core/DnsLeakDetector.h"
#include "../core/Exporter.h"

class MainWindow : public QMainWindow
{
    Q_OBJECT
public:
    explicit MainWindow(QWidget *parent = nullptr);

protected:
    void resizeEvent(QResizeEvent *e) override;
    void closeEvent(QCloseEvent *e) override;

private slots:
    void refresh();
    void onPageRequested(Sidebar::Page page);
    void onProcessSelected(const QString &process);
    void onHistorySample();
    void exportJson();
    void exportCsv();
    void exportPdf();

private:
    void buildLayout();
    void buildMenuBar();
    void applySnapshot(const ProcSnapshot &snap);
    void checkNewAnomalies(const QVector<AnomalyEntry> &anomalies);

    Sidebar *m_sidebar;
    QStackedWidget *m_stack;

    // PAGE 0-10 (existing)
    ConnectionsTab *m_connectionsTab;
    ProcessesTab *m_processesTab;
    RouteMapWidget *m_routeMap;
    DnsTab *m_dnsTab;
    AnomalyTab *m_anomalyTab;
    LoadBalancerTab *m_loadBalancerTab;
    HistoryTab *m_historyTab;
    CostTab *m_costTab;
    TimelineTab *m_timelineTab;
    DnsLeakTab *m_dnsLeakTab;
    BgpTab *m_bgpTab;

    // PAGE 11-14 (new)
    NetworkPerfTab *m_networkPerfTab;
    ThreatMapTab *m_threatMapTab;
    FirewallTab *m_firewallTab;
    TrustTab *m_trustTab;

    AlertPopup *m_alertPopup;
    ProcessDetailOverlay *m_processDetail;
    TrayIcon *m_trayIcon;

    QTimer *m_timer;
    QTimer *m_historyTimer;
    QLabel *m_statusLabel;
    int m_refreshMs = 1000;

    QSet<QString> m_seenAnomalies;
    ProcSnapshot m_lastSnap;

    BgpMonitor *m_bgpMonitor;
    DnsLeakDetector *m_dnsLeakDetector;
    Exporter *m_exporter;
};