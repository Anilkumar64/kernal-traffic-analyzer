#pragma once
#include <QWidget>
#include "../core/RouteEntry.h"
class QSortFilterProxyModel;
class QTableView;
class RouteHopModel;
class RouteModel;

class RoutesTab : public QWidget
{
    Q_OBJECT
public:
    explicit RoutesTab(QWidget *parent = nullptr);
    void updateData(const QVector<RouteEntry> &entries);
private:
    void selectRoute(const QModelIndex &index);
    RouteModel *m_model = nullptr;
    RouteHopModel *m_hopModel = nullptr;
    QSortFilterProxyModel *m_proxy = nullptr;
    QTableView *m_table = nullptr;
};
