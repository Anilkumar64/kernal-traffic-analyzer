/**
 * @file DnsModel.h
 * @brief Table model for DNS resolution records.
 * @details Provides filtering and sorting for domain/IP history exposed by /proc/traffic_analyzer_dns.
 * @author Kernel Traffic Analyzer Project
 * @license MIT
 */
#pragma once

#include "ProcReader.h"

#include <QAbstractTableModel>

/**
 * @brief Qt table model for DNS rows.
 */
class DnsModel : public QAbstractTableModel {
    Q_OBJECT

public:
    /** @brief DNS columns. */
    enum Column { ColIp = 0, ColDomain, ColFirstSeen, ColLastSeen, ColQueryCount, ColumnCount };

    /** @brief Constructs the model. @param parent Optional parent. */
    explicit DnsModel(QObject* parent = nullptr);
    /** @brief Returns row count. @param parent Parent index. @return Visible rows. */
    int rowCount(const QModelIndex& parent = QModelIndex()) const override;
    /** @brief Returns column count. @param parent Parent index. @return Columns. */
    int columnCount(const QModelIndex& parent = QModelIndex()) const override;
    /** @brief Returns data for a cell. @param index Model index. @param role Data role. @return Cell data. */
    QVariant data(const QModelIndex& index, int role = Qt::DisplayRole) const override;
    /** @brief Returns header data. @param section Section. @param orientation Orientation. @param role Role. @return Header data. */
    QVariant headerData(int section, Qt::Orientation orientation, int role = Qt::DisplayRole) const override;
    /** @brief Sorts records. @param column Column. @param order Order. */
    void sort(int column, Qt::SortOrder order = Qt::AscendingOrder) override;

public slots:
    /** @brief Replaces DNS records. @param records Records. */
    void setData(const QVector<DnsRecord>& records);
    /** @brief Applies a live filter. @param text Text. */
    void filter(const QString& text);

private:
    /** @brief Rebuilds filtered indices. */
    void rebuildFilter();

    QVector<DnsRecord> records_;
    QVector<int> filtered_indices_;
    QString filter_text_;
};
