#pragma once

#include <QWidget>
#include "../core/TrafficEntry.h"

class QLineEdit;
class QSortFilterProxyModel;
class QTableView;
class StatCard;
class TrafficModel;
class ToggleSwitch;

class ConnectionsTab : public QWidget
{
    Q_OBJECT
public:
    explicit ConnectionsTab(QWidget *parent = nullptr);
    void updateData(const QVector<TrafficEntry> &entries);

private:
    TrafficModel *m_model = nullptr;
    QSortFilterProxyModel *m_proxy = nullptr;
    QLineEdit *m_filter = nullptr;
    ToggleSwitch *m_showInactive = nullptr;
    QTableView *m_table = nullptr;
    StatCard *m_total = nullptr;
    StatCard *m_inRate = nullptr;
    StatCard *m_outRate = nullptr;
    StatCard *m_processes = nullptr;
};
