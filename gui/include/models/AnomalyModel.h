/**
 * @file AnomalyModel.h
 * @brief Table model for active anomaly records.
 * @details Provides severity coloring, acknowledgement tracking, and descriptions for kernel anomaly flags.
 * @author Kernel Traffic Analyzer Project
 * @license MIT
 */
#pragma once

#include "ProcReader.h"

#include <QAbstractTableModel>
#include <QSet>

/**
 * @brief Qt table model for anomalies.
 */
class AnomalyModel : public QAbstractTableModel {
    Q_OBJECT

public:
    /** @brief Anomaly columns. */
    enum Column { ColPid = 0, ColProcess, ColFlag, ColSeverity, ColDescription, ColFirstDetected, ColCount, ColumnCount };

    /** @brief Constructs the model. @param parent Optional parent. */
    explicit AnomalyModel(QObject* parent = nullptr);
    /** @brief Returns row count. @param parent Parent index. @return Visible row count. */
    int rowCount(const QModelIndex& parent = QModelIndex()) const override;
    /** @brief Returns column count. @param parent Parent index. @return Column count. */
    int columnCount(const QModelIndex& parent = QModelIndex()) const override;
    /** @brief Returns cell data. @param index Index. @param role Role. @return Data. */
    QVariant data(const QModelIndex& index, int role = Qt::DisplayRole) const override;
    /** @brief Returns header data. @param section Section. @param orientation Orientation. @param role Role. @return Header. */
    QVariant headerData(int section, Qt::Orientation orientation, int role = Qt::DisplayRole) const override;
    /** @brief Sorts anomalies. @param column Column. @param order Sort order. */
    void sort(int column, Qt::SortOrder order = Qt::AscendingOrder) override;
    /** @brief Returns whether a critical unacknowledged anomaly exists. @return True when critical active. */
    bool hasCriticalActive() const;

public slots:
    /** @brief Replaces records. @param records New anomaly rows. */
    void setData(const QVector<AnomalyRecord>& records);
    /** @brief Applies filter text. @param text Search text. */
    void filter(const QString& text);
    /** @brief Marks visible row as acknowledged. @param row Visible row. */
    void acknowledgeRow(int row);
    /** @brief Removes acknowledged rows. */
    void clearAcknowledged();

private:
    /** @brief Creates a stable acknowledgement key. @param rec Record. @return Key. */
    QString keyFor(const AnomalyRecord& rec) const;
    /** @brief Describes an anomaly flag. @param flags Flag names. @return Human-readable description. */
    QString descriptionFor(const QString& flags) const;
    /** @brief Rebuilds filtered rows. */
    void rebuildFilter();

    QVector<AnomalyRecord> records_;
    QVector<int> filtered_indices_;
    QString filter_text_;
    QSet<QString> acknowledged_;
};
