/**
 * @file ProcModel.h
 * @brief Table model for per-process traffic aggregates.
 * @details Supports sorting, filtering, anomaly highlighting, and expandable child rows that show top remote connections for a process.
 * @author Kernel Traffic Analyzer Project
 * @license MIT
 */
#pragma once

#include "ProcReader.h"

#include <QAbstractTableModel>
#include <QSet>

/**
 * @brief Qt model for process aggregate rows.
 */
class ProcModel : public QAbstractTableModel {
    Q_OBJECT

public:
    /** @brief Process table columns. */
    enum Column {
        ColPid = 0,
        ColProcess,
        ColConnections,
        ColTcpPct,
        ColUdpPct,
        ColTotalIn,
        ColTotalOut,
        ColRateIn,
        ColRateOut,
        ColAnomaly,
        ColTopRemotes,
        ColumnCount
    };

    /** @brief Constructs the model. @param parent Optional parent. */
    explicit ProcModel(QObject* parent = nullptr);
    /** @brief Returns visible row count. @param parent Parent index. @return Row count. */
    int rowCount(const QModelIndex& parent = QModelIndex()) const override;
    /** @brief Returns column count. @param parent Parent index. @return Column count. */
    int columnCount(const QModelIndex& parent = QModelIndex()) const override;
    /** @brief Returns cell data. @param index Model index. @param role Data role. @return Cell data. */
    QVariant data(const QModelIndex& index, int role = Qt::DisplayRole) const override;
    /** @brief Returns header data. @param section Header section. @param orientation Orientation. @param role Role. @return Header data. */
    QVariant headerData(int section, Qt::Orientation orientation, int role = Qt::DisplayRole) const override;
    /** @brief Sorts model records. @param column Column. @param order Sort order. */
    void sort(int column, Qt::SortOrder order = Qt::AscendingOrder) override;
    /** @brief Returns the process ID for a visible row. @param row Visible row. @return PID if the row is a process row. */
    std::optional<int> pidAt(int row) const;

public slots:
    /** @brief Replaces process records. @param records New process records. */
    void setData(const QVector<ProcRecord>& records);
    /** @brief Supplies connection rows used for expanded process details. @param records Connection records. */
    void setConnections(const QVector<ConnectionRecord>& records);
    /** @brief Applies live filter text. @param text Search text. */
    void filter(const QString& text);
    /** @brief Sets expanded PIDs. @param pids Expanded process IDs. */
    void setExpandedPids(const QSet<int>& pids);

private:
    /** @brief Internal row mapping entry. */
    struct RowRef {
        int procIndex{-1};
        int childIndex{-1};
    };

    /** @brief Rebuilds visible row references. */
    void rebuildRows();
    /** @brief Returns TCP percentage for a process. @param rec Record. @return Percent. */
    double tcpPct(const ProcRecord& rec) const;
    /** @brief Returns UDP percentage for a process. @param rec Record. @return Percent. */
    double udpPct(const ProcRecord& rec) const;
    /** @brief Returns top remote strings for a PID. @param pid Process ID. @return Remote descriptions. */
    QStringList topRemotesForPid(int pid) const;

    QVector<ProcRecord> records_;
    QVector<ConnectionRecord> connections_;
    QVector<int> filtered_indices_;
    QVector<RowRef> rows_;
    QString filter_text_;
    QSet<int> expanded_pids_;
};
