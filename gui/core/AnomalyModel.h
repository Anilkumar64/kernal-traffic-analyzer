#pragma once
#include <QAbstractTableModel>
#include <QVector>
#include "AnomalyEntry.h"

class AnomalyModel : public QAbstractTableModel
{
    Q_OBJECT
public:
    enum Column { Timestamp, Pid, Process, Type, Details, Count };
    explicit AnomalyModel(QObject *parent = nullptr);
    int rowCount(const QModelIndex &parent = {}) const override;
    int columnCount(const QModelIndex &parent = {}) const override;
    QVariant data(const QModelIndex &index, int role = Qt::DisplayRole) const override;
    QVariant headerData(int section, Qt::Orientation orientation, int role) const override;
    void updateData(const QVector<AnomalyEntry> &entries);
    void clear();
private:
    QVector<AnomalyEntry> m_data;
};
