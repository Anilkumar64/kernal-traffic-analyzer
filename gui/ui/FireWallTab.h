#pragma once
#include <QWidget>
#include <QTableWidget>
#include <QLabel>
#include "../core/FirewallManager.h"
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

private:
    void rebuild();

    QTableWidget *m_connTable;     // active connections with block buttons
    QTableWidget *m_rulesTable;    // current firewall rules
    QLabel *m_statusLabel;

    QVector<TrafficEntry> m_conns;
    QVector<ProcEntry> m_procs;
};
