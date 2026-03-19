#pragma once
#include <QAbstractTableModel>
#include <QVector>
#include "TrafficEntry.h"

class TrafficModel : public QAbstractTableModel {
    Q_OBJECT
public:
    enum Col {
        COL_PROCESS=0, COL_DOMAIN, COL_PROTO, COL_STATE,
        COL_SRC, COL_DEST, COL_RATE_OUT, COL_RATE_IN,
        COL_BYTES, COL_DURATION, COL_PID, COL_COUNT
    };
    explicit TrafficModel(QObject *parent = nullptr);
    int rowCount(const QModelIndex &parent = {}) const override;
    int columnCount(const QModelIndex &parent = {}) const override;
    QVariant data(const QModelIndex &index, int role = Qt::DisplayRole) const override;
    QVariant headerData(int section, Qt::Orientation orientation, int role) const override;
    Qt::ItemFlags flags(const QModelIndex &index) const override;
    void updateData(const QVector<TrafficEntry> &entries);
    const TrafficEntry &entryAt(int row) const;
private:
    QVector<TrafficEntry> m_data;
};
