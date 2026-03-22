#pragma once
#include <QWidget>
#include <QPushButton>
#include <QLabel>
#include <QPropertyAnimation>

class Sidebar : public QWidget
{
    Q_OBJECT
public:
    enum Page
    {
        PAGE_CONNECTIONS = 0,
        PAGE_PROCESSES,
        PAGE_ROUTEMAP,
        PAGE_DNS,
        PAGE_ANOMALIES,
        PAGE_LOADBALANCER,
        PAGE_HISTORY,
        PAGE_COST,
        PAGE_TIMELINE,
        PAGE_DNSLEAK,
        PAGE_BGP,
        PAGE_NETWORKPERF,
        PAGE_THREATMAP,
        PAGE_FIREWALL,
        PAGE_TRUST
    };

    explicit Sidebar(QWidget *parent = nullptr);
    void setAnomalyCount(int count);
    void setActivePage(Page page);

signals:
    void pageRequested(Page page);

private slots:
    void toggleCollapse();

private:
    QPushButton *makeNavButton(const QString &label, const QString &icon, Page page);
    void setActive(QPushButton *btn, bool active);
    void applyCollapsed(bool collapsed);

    QPushButton *m_btnCollapse;
    QPushButton *m_btnConnections;
    QPushButton *m_btnProcesses;
    QPushButton *m_btnRouteMap;
    QPushButton *m_btnDns;
    QPushButton *m_btnAnomalies;
    QPushButton *m_btnLoadBalancer;
    QPushButton *m_btnHistory;
    QPushButton *m_btnCost;
    QPushButton *m_btnTimeline;
    QPushButton *m_btnDnsLeak;
    QPushButton *m_btnBgp;
    QPushButton *m_btnNetworkPerf;
    QPushButton *m_btnThreatMap;
    QPushButton *m_btnFirewall;
    QPushButton *m_btnTrust;
    QLabel *m_anomalyBadge;
    QLabel *m_titleLabel;
    QLabel *m_subLabel;
    QLabel *m_liveLabel;
    QWidget *m_logoWidget;

    Page m_activePage = PAGE_CONNECTIONS;
    bool m_collapsed = false;

    static const int EXPANDED_W = 200;
    static const int COLLAPSED_W = 52;
};