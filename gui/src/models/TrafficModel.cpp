/**
 * @file TrafficModel.cpp
 * @brief Implementation of the live connection table model.
 * @details Handles filtering, sorting, formatting, and raw delegate roles for connection data.
 * @author Kernel Traffic Analyzer Project
 * @license MIT
 */
#include "models/TrafficModel.h"

#include "Style.h"

#include <QBrush>
#include <QDateTime>
#include <algorithm>

TrafficModel::TrafficModel(QObject* parent)
    : QAbstractTableModel(parent)
{
}

int TrafficModel::rowCount(const QModelIndex& parent) const
{
    return parent.isValid() ? 0 : filtered_indices_.size();
}

int TrafficModel::columnCount(const QModelIndex& parent) const
{
    return parent.isValid() ? 0 : ColumnCount;
}

QVariant TrafficModel::data(const QModelIndex& index, int role) const
{
    if (!index.isValid() || index.row() < 0 || index.row() >= filtered_indices_.size()) {
        return {};
    }
    const int sourceRow = filtered_indices_.at(index.row());
    if (sourceRow < 0 || sourceRow >= records_.size()) {
        return {};
    }
    const ConnectionRecord& rec = records_.at(sourceRow);

    if (role == Qt::DisplayRole) {
        return valueFor(rec, index.column());
    }
    if (role == Qt::UserRole) {
        switch (index.column()) {
        case ColPid: return rec.pid;
        case ColRateIn: return QVariant::fromValue<qulonglong>(rec.rateIn);
        case ColRateOut: return QVariant::fromValue<qulonglong>(rec.rateOut);
        case ColBytesIn: return QVariant::fromValue<qulonglong>(rec.bytesIn);
        case ColBytesOut: return QVariant::fromValue<qulonglong>(rec.bytesOut);
        case ColDuration: return QVariant::fromValue<qulonglong>(durationSeconds(rec.firstSeen));
        default: return valueFor(rec, index.column());
        }
    }
    if (role == Qt::TextAlignmentRole) {
        if (index.column() == ColPid || index.column() >= ColRateIn) {
            return Qt::AlignVCenter | Qt::AlignRight;
        }
        return Qt::AlignVCenter | Qt::AlignLeft;
    }
    if (role == Qt::ForegroundRole && rec.anomalyFlags != 0) {
        return QBrush(QColor(KtaColors::Warning));
    }
    return {};
}

QVariant TrafficModel::headerData(int section, Qt::Orientation orientation, int role) const
{
    if (orientation != Qt::Horizontal || role != Qt::DisplayRole) {
        return {};
    }
    static const QStringList headers = {
        "PID", "Process", "Protocol", "State", "Local", "Remote", "Domain",
        "Rate↓", "Rate↑", "Bytes↓", "Bytes↑", "Duration"
    };
    return headers.value(section);
}

void TrafficModel::sort(int column, Qt::SortOrder order)
{
    beginResetModel();
    std::stable_sort(records_.begin(), records_.end(), [this, column, order](const ConnectionRecord& a, const ConnectionRecord& b) {
        auto less = [this, column](const ConnectionRecord& left, const ConnectionRecord& right) {
            switch (column) {
            case ColPid: return left.pid < right.pid;
            case ColProto: return left.proto < right.proto;
            case ColState: return left.state < right.state;
            case ColLocal: return QString("%1:%2").arg(left.srcIp).arg(left.srcPort) < QString("%1:%2").arg(right.srcIp).arg(right.srcPort);
            case ColRemote: return QString("%1:%2").arg(left.dstIp).arg(left.dstPort) < QString("%1:%2").arg(right.dstIp).arg(right.dstPort);
            case ColDomain: return left.domain < right.domain;
            case ColRateIn: return left.rateIn < right.rateIn;
            case ColRateOut: return left.rateOut < right.rateOut;
            case ColBytesIn: return left.bytesIn < right.bytesIn;
            case ColBytesOut: return left.bytesOut < right.bytesOut;
            case ColDuration: return durationSeconds(left.firstSeen) < durationSeconds(right.firstSeen);
            default: return left.process < right.process;
            }
        };
        return order == Qt::AscendingOrder ? less(a, b) : less(b, a);
    });
    rebuildFilter();
    endResetModel();
}

std::optional<ConnectionRecord> TrafficModel::recordAt(int row) const
{
    if (row < 0 || row >= filtered_indices_.size()) {
        return std::nullopt;
    }
    const int sourceRow = filtered_indices_.at(row);
    if (sourceRow < 0 || sourceRow >= records_.size()) {
        return std::nullopt;
    }
    return records_.at(sourceRow);
}

QString TrafficModel::rowToPipe(int row) const
{
    const std::optional<ConnectionRecord> rec = recordAt(row);
    if (!rec.has_value()) {
        return {};
    }
    const ConnectionRecord& r = rec.value();
    return QStringList{
        QString::number(r.pid), r.process, r.exe, r.resolved ? "1" : "0", r.state,
        r.dnsResolved ? "1" : "0", r.proto, r.srcIp, QString::number(r.srcPort),
        r.dstIp, QString::number(r.dstPort), r.domain, QString::number(r.bytesIn),
        QString::number(r.bytesOut), QString::number(r.pktsIn), QString::number(r.pktsOut),
        QString::number(r.rateIn), QString::number(r.rateOut), r.firstSeen, r.lastSeen,
        QString::number(r.anomalyFlags)
    }.join('|');
}

void TrafficModel::setWhitelistedPids(const QSet<int>& pids)
{
    beginResetModel();
    whitelisted_pids_ = pids;
    rebuildFilter();
    endResetModel();
}

void TrafficModel::setData(const QVector<ConnectionRecord>& records)
{
    beginResetModel();
    records_ = records;
    rebuildFilter();
    endResetModel();
}

void TrafficModel::filter(const QString& text)
{
    beginResetModel();
    filter_text_ = text.trimmed();
    rebuildFilter();
    endResetModel();
}

void TrafficModel::setProtocolFilter(const QString& proto)
{
    beginResetModel();
    proto_filter_ = proto;
    rebuildFilter();
    endResetModel();
}

void TrafficModel::setStateFilter(const QString& state)
{
    beginResetModel();
    state_filter_ = state;
    rebuildFilter();
    endResetModel();
}

void TrafficModel::rebuildFilter()
{
    filtered_indices_.clear();
    for (int i = 0; i < records_.size(); ++i) {
        if (filterAccepts(records_.at(i))) {
            filtered_indices_.append(i);
        }
    }
}

bool TrafficModel::filterAccepts(const ConnectionRecord& rec) const
{
    if (whitelisted_pids_.contains(rec.pid)) {
        return false;
    }
    if (proto_filter_ != "All" && rec.proto.compare(proto_filter_, Qt::CaseInsensitive) != 0) {
        return false;
    }
    if (state_filter_ != "All") {
        const QString state = rec.state.toUpper();
        if (state_filter_ == "SYN") {
            if (!state.startsWith("SYN")) {
                return false;
            }
        } else if (!state.contains(state_filter_, Qt::CaseInsensitive)) {
            return false;
        }
    }
    if (filter_text_.isEmpty()) {
        return true;
    }
    const QString needle = filter_text_.toLower();
    return QString::number(rec.pid).contains(needle)
        || rec.process.toLower().contains(needle)
        || rec.exe.toLower().contains(needle)
        || rec.srcIp.toLower().contains(needle)
        || rec.dstIp.toLower().contains(needle)
        || rec.domain.toLower().contains(needle)
        || rec.proto.toLower().contains(needle)
        || rec.state.toLower().contains(needle);
}

QVariant TrafficModel::valueFor(const ConnectionRecord& rec, int column) const
{
    switch (column) {
    case ColPid: return rec.pid;
    case ColProcess: return rec.process;
    case ColProto: return rec.proto;
    case ColState: return rec.state;
    case ColLocal: return QString("%1:%2").arg(rec.srcIp).arg(rec.srcPort);
    case ColRemote: return QString("%1:%2").arg(rec.dstIp).arg(rec.dstPort);
    case ColDomain: return rec.domain.isEmpty() ? QString("-") : rec.domain;
    case ColRateIn: return formatRate(rec.rateIn);
    case ColRateOut: return formatRate(rec.rateOut);
    case ColBytesIn: return formatBytes(rec.bytesIn);
    case ColBytesOut: return formatBytes(rec.bytesOut);
    case ColDuration: {
        const quint64 seconds = durationSeconds(rec.firstSeen);
        return QString("%1:%2:%3")
            .arg(seconds / 3600, 2, 10, QLatin1Char('0'))
            .arg((seconds / 60) % 60, 2, 10, QLatin1Char('0'))
            .arg(seconds % 60, 2, 10, QLatin1Char('0'));
    }
    default: return {};
    }
}

quint64 TrafficModel::durationSeconds(const QString& firstSeen) const
{
    bool ok = false;
    const qint64 epoch = firstSeen.toLongLong(&ok);
    if (ok && epoch > 0) {
        const qint64 now = QDateTime::currentSecsSinceEpoch();
        return static_cast<quint64>(std::max<qint64>(0, now - epoch));
    }
    const QDateTime parsed = QDateTime::fromString(firstSeen, Qt::ISODate);
    if (parsed.isValid()) {
        return static_cast<quint64>(std::max<qint64>(0, parsed.secsTo(QDateTime::currentDateTimeUtc())));
    }
    return 0;
}
