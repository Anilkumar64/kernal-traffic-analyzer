#pragma once
#include <QWidget>
#include "../core/TrafficEntry.h"
class QCheckBox;
class QLineEdit;
class QSortFilterProxyModel;
class QTableView;
class TrafficModel;

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
    QCheckBox *m_showInactive = nullptr;
    QTableView *m_table = nullptr;
};
