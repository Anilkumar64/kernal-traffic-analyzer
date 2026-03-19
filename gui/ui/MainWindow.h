#pragma once
#include <QMainWindow>
#include <QStackedWidget>
#include <QTimer>
#include <QLabel>
#include "Sidebar.h"
#include "ConnectionsTab.h"
#include "ProcessesTab.h"
#include "RouteMapWidget.h"
#include "DnsTab.h"
#include "AnomalyTab.h"
#include "../core/ProcReader.h"

class MainWindow : public QMainWindow
{
    Q_OBJECT
public:
    explicit MainWindow(QWidget *parent = nullptr);

private slots:
    void refresh();
    void onPageRequested(Sidebar::Page page);

private:
    void buildLayout();
    void applySnapshot(const ProcSnapshot &snap);

    Sidebar        *m_sidebar;
    QStackedWidget *m_stack;
    ConnectionsTab *m_connectionsTab;
    ProcessesTab   *m_processesTab;
    RouteMapWidget *m_routeMap;
    DnsTab         *m_dnsTab;
    AnomalyTab     *m_anomalyTab;
    QTimer         *m_timer;
    QLabel         *m_statusLabel;
    int             m_refreshMs = 1000;
};
