#pragma once
#include <QMainWindow>
#include "../core/ProcReader.h"
class AnomalyTab;
class ConnectionsTab;
class DnsTab;
class HistoryTab;
class NetworkPerfTab;
class ProcessesTab;
class RoutesTab;
class Sidebar;
class QStackedWidget;
class QTimer;

class MainWindow : public QMainWindow
{
    Q_OBJECT
public:
    explicit MainWindow(QWidget *parent = nullptr);
private:
    void refresh();
    void writeHistory();
    void updateStatusBar();
    void exportJson();
    void exportCsv();

    ProcSnapshot m_snap;
    Sidebar *m_sidebar = nullptr;
    QStackedWidget *m_stack = nullptr;
    ConnectionsTab *m_connectionsTab = nullptr;
    ProcessesTab *m_processesTab = nullptr;
    DnsTab *m_dnsTab = nullptr;
    AnomalyTab *m_anomalyTab = nullptr;
    RoutesTab *m_routesTab = nullptr;
    HistoryTab *m_historyTab = nullptr;
    NetworkPerfTab *m_networkPerfTab = nullptr;
    QTimer *m_timer = nullptr;
    QTimer *m_historyTimer = nullptr;
};
