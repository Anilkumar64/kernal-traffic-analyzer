/**
 * @file DnsModel.cpp
 * @brief Implementation of the DNS table model.
 * @details Adds simple substring filtering and stable sorting for DNS rows.
 * @author Kernel Traffic Analyzer Project
 * @license MIT
 */
#include "models/DnsModel.h"

#include <algorithm>

DnsModel::DnsModel(QObject* parent)
    : QAbstractTableModel(parent)
{
}

int DnsModel::rowCount(const QModelIndex& parent) const
{
    return parent.isValid() ? 0 : filtered_indices_.size();
}

int DnsModel::columnCount(const QModelIndex& parent) const
{
    return parent.isValid() ? 0 : ColumnCount;
}

QVariant DnsModel::data(const QModelIndex& index, int role) const
{
    if (!index.isValid() || index.row() < 0 || index.row() >= filtered_indices_.size()) {
        return {};
    }
    const int sourceRow = filtered_indices_.at(index.row());
    if (sourceRow < 0 || sourceRow >= records_.size()) {
        return {};
    }
    const DnsRecord& rec = records_.at(sourceRow);
    if (role == Qt::DisplayRole || role == Qt::UserRole) {
        switch (index.column()) {
        case ColIp: return rec.ip;
        case ColDomain: return rec.domain;
        case ColFirstSeen: return rec.firstSeen;
        case ColLastSeen: return rec.lastSeen;
        case ColQueryCount: return rec.queryCount;
        default: return {};
        }
    }
    if (role == Qt::TextAlignmentRole && index.column() == ColQueryCount) {
        return QVariant::fromValue(Qt::Alignment(Qt::AlignVCenter | Qt::AlignRight));
    }
    return {};
}

QVariant DnsModel::headerData(int section, Qt::Orientation orientation, int role) const
{
    if (orientation != Qt::Horizontal || role != Qt::DisplayRole) {
        return {};
    }
    static const QStringList headers = {"IP", "Domain", "First Seen", "Last Seen", "Query Count"};
    return headers.value(section);
}

void DnsModel::sort(int column, Qt::SortOrder order)
{
    beginResetModel();
    std::stable_sort(records_.begin(), records_.end(), [column, order](const DnsRecord& a, const DnsRecord& b) {
        auto less = [column](const DnsRecord& left, const DnsRecord& right) {
            switch (column) {
            case ColIp: return left.ip < right.ip;
            case ColDomain: return left.domain < right.domain;
            case ColFirstSeen: return left.firstSeen < right.firstSeen;
            case ColLastSeen: return left.lastSeen < right.lastSeen;
            case ColQueryCount: return left.queryCount < right.queryCount;
            default: return false;
            }
        };
        return order == Qt::AscendingOrder ? less(a, b) : less(b, a);
    });
    rebuildFilter();
    endResetModel();
}

void DnsModel::setData(const QVector<DnsRecord>& records)
{
    beginResetModel();
    records_ = records;
    rebuildFilter();
    endResetModel();
}

void DnsModel::filter(const QString& text)
{
    beginResetModel();
    filter_text_ = text.trimmed().toLower();
    rebuildFilter();
    endResetModel();
}

void DnsModel::rebuildFilter()
{
    filtered_indices_.clear();
    for (int i = 0; i < records_.size(); ++i) {
        const DnsRecord& rec = records_.at(i);
        if (filter_text_.isEmpty()
            || rec.domain.toLower().contains(filter_text_)
            || rec.ip.toLower().contains(filter_text_)) {
            filtered_indices_.append(i);
        }
    }
}
