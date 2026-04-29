#pragma once
#include <QWidget>
#include "../core/ProcEntry.h"
#include "../core/TrafficEntry.h"
class QLabel;
class QLineEdit;
class QSortFilterProxyModel;
class QTableView;
class ProcModel;

class ProcessesTab : public QWidget
{
    Q_OBJECT
public:
    explicit ProcessesTab(QWidget *parent = nullptr);
    void updateData(const QVector<ProcEntry> &processes, const QVector<TrafficEntry> &connections);
private:
    void showDetails(const QModelIndex &index);
    ProcModel *m_model = nullptr;
    QSortFilterProxyModel *m_proxy = nullptr;
    QLineEdit *m_filter = nullptr;
    QTableView *m_table = nullptr;
    QLabel *m_detail = nullptr;
    QVector<TrafficEntry> m_connections;
};
