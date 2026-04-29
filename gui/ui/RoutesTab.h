#pragma once

#include <QWidget>
#include "../core/RouteEntry.h"

class QLabel;
class QSortFilterProxyModel;
class QStackedWidget;
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
    QStackedWidget *m_hopStack = nullptr;
    QLabel *m_hopTitle = nullptr;
};
