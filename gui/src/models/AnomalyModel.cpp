/**
 * @file AnomalyModel.cpp
 * @brief Implementation of the anomaly table model.
 * @details Handles filtering, acknowledgement, severity highlighting, and flag descriptions.
 * @author Kernel Traffic Analyzer Project
 * @license MIT
 */
#include "models/AnomalyModel.h"

#include "Style.h"

#include <QBrush>
#include <algorithm>

AnomalyModel::AnomalyModel(QObject* parent)
    : QAbstractTableModel(parent)
{
}

int AnomalyModel::rowCount(const QModelIndex& parent) const
{
    return parent.isValid() ? 0 : filtered_indices_.size();
}

int AnomalyModel::columnCount(const QModelIndex& parent) const
{
    return parent.isValid() ? 0 : ColumnCount;
}

QVariant AnomalyModel::data(const QModelIndex& index, int role) const
{
    if (!index.isValid() || index.row() < 0 || index.row() >= filtered_indices_.size()) {
        return {};
    }
    const int sourceRow = filtered_indices_.at(index.row());
    if (sourceRow < 0 || sourceRow >= records_.size()) {
        return {};
    }
    const AnomalyRecord& rec = records_.at(sourceRow);

    if (role == Qt::DisplayRole) {
        switch (index.column()) {
        case ColPid: return rec.pid;
        case ColProcess: return rec.process;
        case ColFlag: return rec.flagNames;
        case ColSeverity: return rec.severity;
        case ColDescription: return descriptionFor(rec.flagNames);
        case ColFirstDetected: return rec.firstSeen;
        case ColCount: return 1;
        default: return {};
        }
    }
    if (role == Qt::UserRole) {
        return index.column() == ColPid ? QVariant(rec.pid) : data(index, Qt::DisplayRole);
    }
    if (role == Qt::BackgroundRole) {
        if (rec.severity.compare("CRITICAL", Qt::CaseInsensitive) == 0) {
            return QBrush(QColor(248, 81, 73, 54));
        }
        if (rec.severity.compare("WARNING", Qt::CaseInsensitive) == 0) {
            return QBrush(QColor(227, 179, 65, 44));
        }
    }
    if (role == Qt::ForegroundRole) {
        return QBrush(severityColor(rec.severity));
    }
    if (role == Qt::TextAlignmentRole && (index.column() == ColPid || index.column() == ColCount)) {
        return Qt::AlignVCenter | Qt::AlignRight;
    }
    return {};
}

QVariant AnomalyModel::headerData(int section, Qt::Orientation orientation, int role) const
{
    if (orientation != Qt::Horizontal || role != Qt::DisplayRole) {
        return {};
    }
    static const QStringList headers = {"PID", "Process", "Flag", "Severity", "Description", "First Detected", "Count"};
    return headers.value(section);
}

void AnomalyModel::sort(int column, Qt::SortOrder order)
{
    beginResetModel();
    std::stable_sort(records_.begin(), records_.end(), [column, order](const AnomalyRecord& a, const AnomalyRecord& b) {
        auto less = [column](const AnomalyRecord& left, const AnomalyRecord& right) {
            switch (column) {
            case ColPid: return left.pid < right.pid;
            case ColProcess: return left.process < right.process;
            case ColFlag: return left.flagNames < right.flagNames;
            case ColSeverity: return left.severity < right.severity;
            case ColFirstDetected: return left.firstSeen < right.firstSeen;
            default: return left.anomalyFlags < right.anomalyFlags;
            }
        };
        return order == Qt::AscendingOrder ? less(a, b) : less(b, a);
    });
    rebuildFilter();
    endResetModel();
}

bool AnomalyModel::hasCriticalActive() const
{
    for (const AnomalyRecord& rec : records_) {
        if (rec.severity.compare("CRITICAL", Qt::CaseInsensitive) == 0 && !acknowledged_.contains(keyFor(rec))) {
            return true;
        }
    }
    return false;
}

void AnomalyModel::setData(const QVector<AnomalyRecord>& records)
{
    beginResetModel();
    records_ = records;
    rebuildFilter();
    endResetModel();
}

void AnomalyModel::filter(const QString& text)
{
    beginResetModel();
    filter_text_ = text.trimmed().toLower();
    rebuildFilter();
    endResetModel();
}

void AnomalyModel::acknowledgeRow(int row)
{
    if (row < 0 || row >= filtered_indices_.size()) {
        return;
    }
    const int sourceRow = filtered_indices_.at(row);
    if (sourceRow < 0 || sourceRow >= records_.size()) {
        return;
    }
    beginResetModel();
    acknowledged_.insert(keyFor(records_.at(sourceRow)));
    rebuildFilter();
    endResetModel();
}

void AnomalyModel::clearAcknowledged()
{
    beginResetModel();
    QVector<AnomalyRecord> kept;
    for (const AnomalyRecord& rec : records_) {
        if (!acknowledged_.contains(keyFor(rec))) {
            kept.append(rec);
        }
    }
    records_ = kept;
    acknowledged_.clear();
    rebuildFilter();
    endResetModel();
}

QString AnomalyModel::keyFor(const AnomalyRecord& rec) const
{
    return QString("%1|%2|%3|%4").arg(rec.pid).arg(rec.process, rec.flagNames, rec.firstSeen);
}

QString AnomalyModel::descriptionFor(const QString& flags) const
{
    const QString normalized = flags.toUpper();
    QStringList descriptions;
    if (normalized.contains("CONN_BURST")) {
        descriptions << "≥20 new connections/second detected";
    }
    if (normalized.contains("PORT_SCAN")) {
        descriptions << "≥15 unique destination ports contacted";
    }
    if (normalized.contains("HIGH_CONNS")) {
        descriptions << "≥200 simultaneous connections";
    }
    if (normalized.contains("SYN_FLOOD")) {
        descriptions << "≥80% of connections in SYN state";
    }
    if (normalized.contains("HIGH_BW")) {
        descriptions << "Bandwidth exceeds 10 MB/s";
    }
    return descriptions.isEmpty() ? QString("Kernel anomaly flag %1").arg(flags) : descriptions.join("; ");
}

void AnomalyModel::rebuildFilter()
{
    filtered_indices_.clear();
    for (int i = 0; i < records_.size(); ++i) {
        const AnomalyRecord& rec = records_.at(i);
        if (acknowledged_.contains(keyFor(rec))) {
            continue;
        }
        if (filter_text_.isEmpty()
            || rec.process.toLower().contains(filter_text_)
            || rec.flagNames.toLower().contains(filter_text_)
            || rec.severity.toLower().contains(filter_text_)
            || QString::number(rec.pid).contains(filter_text_)) {
            filtered_indices_.append(i);
        }
    }
}
