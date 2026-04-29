/**
 * @file TrafficModel.h
 * @brief Table model for live connection records.
 * @details Presents /proc/traffic_analyzer rows with combined text, protocol, and state filtering plus sortable raw values for numeric columns.
 * @author Kernel Traffic Analyzer Project
 * @license MIT
 */
#pragma once

#include "ProcReader.h"

#include <QAbstractTableModel>
#include <QSet>

/**
 * @brief Qt table model for active network connections.
 */
class TrafficModel : public QAbstractTableModel {
    Q_OBJECT

public:
    /** @brief Connection table columns. */
    enum Column {
        ColPid = 0,
        ColProcess,
        ColProto,
        ColState,
        ColLocal,
        ColRemote,
        ColDomain,
        ColRateIn,
        ColRateOut,
        ColBytesIn,
        ColBytesOut,
        ColDuration,
        ColumnCount
    };

    /** @brief Constructs the model. @param parent Optional parent. */
    explicit TrafficModel(QObject* parent = nullptr);

    /** @brief Returns visible row count. @param parent Parent index. @return Row count. */
    int rowCount(const QModelIndex& parent = QModelIndex()) const override;
    /** @brief Returns column count. @param parent Parent index. @return Column count. */
    int columnCount(const QModelIndex& parent = QModelIndex()) const override;
    /** @brief Returns display, decoration, or raw-role data. @param index Model index. @param role Data role. @return Cell data. */
    QVariant data(const QModelIndex& index, int role = Qt::DisplayRole) const override;
    /** @brief Returns header data. @param section Header section. @param orientation Header orientation. @param role Data role. @return Header value. */
    QVariant headerData(int section, Qt::Orientation orientation, int role = Qt::DisplayRole) const override;
    /** @brief Sorts records by column. @param column Sort column. @param order Sort order. */
    void sort(int column, Qt::SortOrder order = Qt::AscendingOrder) override;

    /** @brief Returns a record for a visible row. @param row Visible row. @return Optional record. */
    std::optional<ConnectionRecord> recordAt(int row) const;
    /** @brief Creates a pipe-delimited row for copying. @param row Visible row. @return Row text. */
    QString rowToPipe(int row) const;
    /** @brief Sets hidden process IDs for whitelist support. @param pids PIDs to hide. */
    void setWhitelistedPids(const QSet<int>& pids);

public slots:
    /** @brief Replaces model records. @param records New connection records. */
    void setData(const QVector<ConnectionRecord>& records);
    /** @brief Applies a text filter. @param text Filter text. */
    void filter(const QString& text);
    /** @brief Applies a protocol filter. @param proto Protocol label or All. */
    void setProtocolFilter(const QString& proto);
    /** @brief Applies a state filter. @param state State label or All. */
    void setStateFilter(const QString& state);

private:
    /** @brief Rebuilds the visible index list. */
    void rebuildFilter();
    /** @brief Tests if a record is visible for the active filters. @param rec Record. @return True when accepted. */
    bool filterAccepts(const ConnectionRecord& rec) const;
    /** @brief Returns display data for a record column. @param rec Record. @param column Column. @return Value. */
    QVariant valueFor(const ConnectionRecord& rec, int column) const;
    /** @brief Parses firstSeen and returns elapsed seconds. @param firstSeen Timestamp text. @return Seconds since first seen. */
    quint64 durationSeconds(const QString& firstSeen) const;

    QVector<ConnectionRecord> records_;
    QVector<int> filtered_indices_;
    QString filter_text_;
    QString proto_filter_{"All"};
    QString state_filter_{"All"};
    QSet<int> whitelisted_pids_;
};
