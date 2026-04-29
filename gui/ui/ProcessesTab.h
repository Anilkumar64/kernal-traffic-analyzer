#pragma once

#include <QWidget>
#include "../core/ProcEntry.h"
#include "../core/TrafficEntry.h"

class QLineEdit;
class QSortFilterProxyModel;
class QTreeView;
class ProcessTreeModel;

class ProcessesTab : public QWidget
{
    Q_OBJECT
public:
    explicit ProcessesTab(QWidget *parent = nullptr);
    void updateData(const QVector<ProcEntry> &processes, const QVector<TrafficEntry> &connections);

private:
    ProcessTreeModel *m_model = nullptr;
    QSortFilterProxyModel *m_proxy = nullptr;
    QLineEdit *m_filter = nullptr;
    QTreeView *m_tree = nullptr;
};
