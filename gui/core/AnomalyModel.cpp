#include "AnomalyModel.h"
#include "../ui/Style.h"
#include <QBrush>
#include <QDateTime>

AnomalyModel::AnomalyModel(QObject *parent) : QAbstractTableModel(parent) {}
int AnomalyModel::rowCount(const QModelIndex &) const { return m_data.size(); }
int AnomalyModel::columnCount(const QModelIndex &) const { return Count; }

QVariant AnomalyModel::data(const QModelIndex &index, int role) const
{
    if (!index.isValid() || index.row() >= m_data.size()) return {};
    const auto &e = m_data.at(index.row());
    if (role == Qt::DisplayRole) {
        switch (index.column()) {
        case Timestamp: return QDateTime::fromSecsSinceEpoch(e.timestamp).toString("yyyy-MM-dd hh:mm:ss");
        case Pid: return e.pid;
        case Process: return e.process;
        case Type: return e.anomaly;
        case Details: return QString("new=%1 ports=%2 conns=%3 syn=%4 out=%5 in=%6")
            .arg(e.newConnsLastSec).arg(e.uniquePortsLastSec).arg(e.totalConns)
            .arg(e.synPending).arg(e.formatRate(e.rateOutBps)).arg(e.formatRate(e.rateInBps));
        default: return {};
        }
    }
    if (role == Qt::BackgroundRole && (e.anomaly == "SYN_FLOOD" || e.anomaly == "PORT_SCAN")) return QBrush(KtaColors::RedD);
    if (role == Qt::ForegroundRole && index.column() == Type) return QBrush(KtaColors::Red);
    return {};
}

QVariant AnomalyModel::headerData(int section, Qt::Orientation orientation, int role) const
{
    if (orientation != Qt::Horizontal || role != Qt::DisplayRole) return {};
    static const QStringList headers = {"TIMESTAMP", "PID", "PROCESS", "ANOMALY TYPE", "DETAILS"};
    return headers.value(section);
}

void AnomalyModel::updateData(const QVector<AnomalyEntry> &entries)
{
    beginResetModel();
    m_data = entries;
    endResetModel();
}

void AnomalyModel::clear()
{
    beginResetModel();
    m_data.clear();
    endResetModel();
}
