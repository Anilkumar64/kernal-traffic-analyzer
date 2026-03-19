#pragma once
#include <QAbstractTableModel>
#include <QVector>
#include "ProcEntry.h"

class ProcModel : public QAbstractTableModel {
    Q_OBJECT
public:
    enum Col {
        COL_PROCESS=0, COL_EXE, COL_CONNS, COL_RATE_OUT, COL_RATE_IN,
        COL_BYTES, COL_TCP_PCT, COL_ANOMALY, COL_TOP_DEST, COL_PID, COL_COUNT
    };
    explicit ProcModel(QObject *parent = nullptr);
    int rowCount(const QModelIndex &parent = {}) const override;
    int columnCount(const QModelIndex &parent = {}) const override;
    QVariant data(const QModelIndex &index, int role = Qt::DisplayRole) const override;
    QVariant headerData(int section, Qt::Orientation orientation, int role) const override;
    Qt::ItemFlags flags(const QModelIndex &index) const override;
    void updateData(const QVector<ProcEntry> &entries);
    const ProcEntry &entryAt(int row) const;
private:
    QVector<ProcEntry> m_data;
};
