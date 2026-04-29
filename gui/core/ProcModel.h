#pragma once
#include <QAbstractTableModel>
#include <QVector>
#include "ProcEntry.h"

class ProcModel : public QAbstractTableModel
{
    Q_OBJECT
public:
    enum Column { Pid, Process, Exe, Connections, InTotal, OutTotal, InRate, OutRate, Count };
    explicit ProcModel(QObject *parent = nullptr);
    int rowCount(const QModelIndex &parent = {}) const override;
    int columnCount(const QModelIndex &parent = {}) const override;
    QVariant data(const QModelIndex &index, int role = Qt::DisplayRole) const override;
    QVariant headerData(int section, Qt::Orientation orientation, int role) const override;
    void updateData(const QVector<ProcEntry> &entries);
    [[nodiscard]] const ProcEntry &entryAt(int row) const;
private:
    QVector<ProcEntry> m_data;
};
