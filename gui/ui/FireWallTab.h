#pragma once
#include <QWidget>
#include <QTableWidget>
#include <QLabel>
#include "../core/FirewallManager.h"
#include "../core/BandwidthThrottler.h"
#include "../core/TrafficEntry.h"
#include "../core/ProcEntry.h"

class FirewallTab : public QWidget
{
    Q_OBJECT
public:
    explicit FirewallTab(QWidget *parent = nullptr);
    void updateData(const QVector<TrafficEntry> &conns,
                    const QVector<ProcEntry> &procs);

private slots:
    void onRulesChanged();
    void blockSelected();
    void unblockSelected();

private:
    void rebuild();
    void rebuildThrottleTable();

    QTableWidget *m_connTable;     // active connections with block buttons
    QTableWidget *m_rulesTable;    // current firewall rules
    QTableWidget *m_throttleTable; // bandwidth throttle rules
    QLabel *m_statusLabel;

    QVector<TrafficEntry> m_conns;
    QVector<ProcEntry> m_procs;
};