/**
 * @file ProcModel.cpp
 * @brief Implementation of the process aggregate model.
 * @details Builds a filtered row map with optional child rows and exposes raw values for delegates and sorting.
 * @author Kernel Traffic Analyzer Project
 * @license MIT
 */
#include "models/ProcModel.h"

#include "Style.h"

#include <QBrush>
#include <QFont>
#include <algorithm>

ProcModel::ProcModel(QObject* parent)
    : QAbstractTableModel(parent)
{
}

int ProcModel::rowCount(const QModelIndex& parent) const
{
    return parent.isValid() ? 0 : rows_.size();
}

int ProcModel::columnCount(const QModelIndex& parent) const
{
    return parent.isValid() ? 0 : ColumnCount;
}

QVariant ProcModel::data(const QModelIndex& index, int role) const
{
    if (!index.isValid() || index.row() < 0 || index.row() >= rows_.size()) {
        return {};
    }
    const RowRef ref = rows_.at(index.row());
    if (ref.procIndex < 0 || ref.procIndex >= records_.size()) {
        return {};
    }
    const ProcRecord& rec = records_.at(ref.procIndex);
    const bool isChild = ref.childIndex >= 0;

    if (isChild) {
        const QStringList remotes = topRemotesForPid(rec.pid);
        const QString text = remotes.value(ref.childIndex);
        if (role == Qt::DisplayRole) {
            return index.column() == ColProcess ? QString("  %1").arg(text) : QVariant();
        }
        if (role == Qt::ForegroundRole) {
            return QBrush(QColor(KtaColors::TextMuted));
        }
        if (role == Qt::FontRole) {
            QFont font;
            font.setItalic(true);
            return font;
        }
        return {};
    }

    if (role == Qt::DisplayRole) {
        switch (index.column()) {
        case ColPid: return rec.pid;
        case ColProcess: return rec.process;
        case ColConnections: return rec.connections;
        case ColTcpPct: return QString("%1%").arg(tcpPct(rec), 0, 'f', 1);
        case ColUdpPct: return QString("%1%").arg(udpPct(rec), 0, 'f', 1);
        case ColTotalIn: return formatBytes(rec.totalIn);
        case ColTotalOut: return formatBytes(rec.totalOut);
        case ColRateIn: return formatRate(rec.rateIn);
        case ColRateOut: return formatRate(rec.rateOut);
        case ColAnomaly: return rec.anomalyFlags == 0 ? QString("None") : QString::number(rec.anomalyFlags);
        case ColTopRemotes: return topRemotesForPid(rec.pid).join(", ");
        default: return {};
        }
    }
    if (role == Qt::UserRole) {
        switch (index.column()) {
        case ColPid: return rec.pid;
        case ColConnections: return rec.connections;
        case ColTcpPct: return tcpPct(rec);
        case ColUdpPct: return udpPct(rec);
        case ColTotalIn: return QVariant::fromValue<qulonglong>(rec.totalIn);
        case ColTotalOut: return QVariant::fromValue<qulonglong>(rec.totalOut);
        case ColRateIn: return QVariant::fromValue<qulonglong>(rec.rateIn);
        case ColRateOut: return QVariant::fromValue<qulonglong>(rec.rateOut);
        case ColAnomaly: return rec.anomalyFlags;
        default: return rec.process;
        }
    }
    if (role == Qt::BackgroundRole && rec.anomalyFlags != 0) {
        return QBrush(QColor(248, 81, 73, 44));
    }
    if (role == Qt::TextAlignmentRole && index.column() != ColProcess && index.column() != ColTopRemotes) {
        return Qt::AlignVCenter | Qt::AlignRight;
    }
    return {};
}

QVariant ProcModel::headerData(int section, Qt::Orientation orientation, int role) const
{
    if (orientation != Qt::Horizontal || role != Qt::DisplayRole) {
        return {};
    }
    static const QStringList headers = {
        "PID", "Process", "Connections", "TCP%", "UDP%", "Total↓", "Total↑",
        "Rate↓", "Rate↑", "Anomaly", "Top Remotes"
    };
    return headers.value(section);
}

void ProcModel::sort(int column, Qt::SortOrder order)
{
    beginResetModel();
    std::stable_sort(records_.begin(), records_.end(), [this, column, order](const ProcRecord& a, const ProcRecord& b) {
        auto less = [this, column](const ProcRecord& left, const ProcRecord& right) {
            switch (column) {
            case ColPid: return left.pid < right.pid;
            case ColConnections: return left.connections < right.connections;
            case ColTcpPct: return tcpPct(left) < tcpPct(right);
            case ColUdpPct: return udpPct(left) < udpPct(right);
            case ColTotalIn: return left.totalIn < right.totalIn;
            case ColTotalOut: return left.totalOut < right.totalOut;
            case ColRateIn: return left.rateIn < right.rateIn;
            case ColRateOut: return left.rateOut < right.rateOut;
            case ColAnomaly: return left.anomalyFlags < right.anomalyFlags;
            default: return left.process < right.process;
            }
        };
        return order == Qt::AscendingOrder ? less(a, b) : less(b, a);
    });
    rebuildRows();
    endResetModel();
}

std::optional<int> ProcModel::pidAt(int row) const
{
    if (row < 0 || row >= rows_.size()) {
        return std::nullopt;
    }
    const RowRef ref = rows_.at(row);
    if (ref.childIndex >= 0 || ref.procIndex < 0 || ref.procIndex >= records_.size()) {
        return std::nullopt;
    }
    return records_.at(ref.procIndex).pid;
}

void ProcModel::setData(const QVector<ProcRecord>& records)
{
    beginResetModel();
    records_ = records;
    rebuildRows();
    endResetModel();
}

void ProcModel::setConnections(const QVector<ConnectionRecord>& records)
{
    beginResetModel();
    connections_ = records;
    rebuildRows();
    endResetModel();
}

void ProcModel::filter(const QString& text)
{
    beginResetModel();
    filter_text_ = text.trimmed().toLower();
    rebuildRows();
    endResetModel();
}

void ProcModel::setExpandedPids(const QSet<int>& pids)
{
    beginResetModel();
    expanded_pids_ = pids;
    rebuildRows();
    endResetModel();
}

void ProcModel::rebuildRows()
{
    rows_.clear();
    filtered_indices_.clear();
    for (int i = 0; i < records_.size(); ++i) {
        const ProcRecord& rec = records_.at(i);
        const bool accepted = filter_text_.isEmpty()
            || rec.process.toLower().contains(filter_text_)
            || QString::number(rec.pid).contains(filter_text_);
        if (!accepted) {
            continue;
        }
        filtered_indices_.append(i);
        rows_.append(RowRef{i, -1});
        if (expanded_pids_.contains(rec.pid)) {
            const int childCount = std::min(5, topRemotesForPid(rec.pid).size());
            for (int child = 0; child < childCount; ++child) {
                rows_.append(RowRef{i, child});
            }
        }
    }
}

double ProcModel::tcpPct(const ProcRecord& rec) const
{
    return rec.connections <= 0 ? 0.0 : (static_cast<double>(rec.tcpCount) / static_cast<double>(rec.connections)) * 100.0;
}

double ProcModel::udpPct(const ProcRecord& rec) const
{
    return rec.connections <= 0 ? 0.0 : (static_cast<double>(rec.udpCount) / static_cast<double>(rec.connections)) * 100.0;
}

QStringList ProcModel::topRemotesForPid(int pid) const
{
    QVector<ConnectionRecord> matches;
    for (const ConnectionRecord& conn : connections_) {
        if (conn.pid == pid) {
            matches.append(conn);
        }
    }
    std::stable_sort(matches.begin(), matches.end(), [](const ConnectionRecord& a, const ConnectionRecord& b) {
        return (a.rateIn + a.rateOut) > (b.rateIn + b.rateOut);
    });
    QStringList rows;
    for (int i = 0; i < matches.size() && i < 5; ++i) {
        const ConnectionRecord& c = matches.at(i);
        rows.append(QString("%1 %2:%3  %4")
            .arg(c.proto, c.dstIp)
            .arg(c.dstPort)
            .arg(formatRate(c.rateIn + c.rateOut)));
    }
    return rows;
}
