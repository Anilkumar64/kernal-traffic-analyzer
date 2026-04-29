#pragma once
#include <QAbstractTableModel>
#include <QVector>
#include "DnsEntry.h"

class DnsModel : public QAbstractTableModel
{
    Q_OBJECT
public:
    enum Column { Ip, Domain, Ttl, FirstSeen, LastSeen, QueryCount, Count };
    explicit DnsModel(QObject *parent = nullptr);
    int rowCount(const QModelIndex &parent = {}) const override;
    int columnCount(const QModelIndex &parent = {}) const override;
    QVariant data(const QModelIndex &index, int role = Qt::DisplayRole) const override;
    QVariant headerData(int section, Qt::Orientation orientation, int role) const override;
    void updateData(const QVector<DnsEntry> &entries);
private:
    QVector<DnsEntry> m_data;
};
