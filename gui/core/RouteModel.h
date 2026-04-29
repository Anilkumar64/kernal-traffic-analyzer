#pragma once
#include <QAbstractTableModel>
#include <QVector>
#include "RouteEntry.h"

class RouteModel : public QAbstractTableModel
{
    Q_OBJECT
public:
    enum Column { Destination, Domain, Hops, LastTraced, Count };
    explicit RouteModel(QObject *parent = nullptr);
    int rowCount(const QModelIndex &parent = {}) const override;
    int columnCount(const QModelIndex &parent = {}) const override;
    QVariant data(const QModelIndex &index, int role = Qt::DisplayRole) const override;
    QVariant headerData(int section, Qt::Orientation orientation, int role) const override;
    void updateData(const QVector<RouteEntry> &entries);
    [[nodiscard]] const RouteEntry &entryAt(int row) const;
private:
    QVector<RouteEntry> m_data;
};

class RouteHopModel : public QAbstractTableModel
{
    Q_OBJECT
public:
    enum Column { HopNumber, Ip, Rtt, City, Asn, Count };
    explicit RouteHopModel(QObject *parent = nullptr);
    int rowCount(const QModelIndex &parent = {}) const override;
    int columnCount(const QModelIndex &parent = {}) const override;
    QVariant data(const QModelIndex &index, int role = Qt::DisplayRole) const override;
    QVariant headerData(int section, Qt::Orientation orientation, int role) const override;
    void updateData(const QVector<RouteHop> &entries);
private:
    QVector<RouteHop> m_data;
};
