#include "TrafficModel.h"
#include <QBrush>
#include <QFont>

// color helpers inline — no Style.h dependency
static QColor clrPrimary()  { return QColor("#e6edf3"); }
static QColor clrSecond()   { return QColor("#8b949e"); }
static QColor clrMuted()    { return QColor("#484f58"); }
static QColor clrLink()     { return QColor("#58a6ff"); }
static QColor clrBgBase()   { return QColor("#0d1117"); }

static QColor forState(const QString &s) {
    if (s == "ESTABLISHED") return QColor("#3fb950");
    if (s == "UDP_ACTIVE")  return QColor("#79c0ff");
    if (s == "SYN_SENT")    return QColor("#d29922");
    if (s == "SYN_RECV")    return QColor("#d29922");
    if (s == "FIN_WAIT")    return QColor("#8b949e");
    return QColor("#484f58");
}

TrafficModel::TrafficModel(QObject *parent) : QAbstractTableModel(parent) {}
int TrafficModel::rowCount(const QModelIndex &) const { return m_data.size(); }
int TrafficModel::columnCount(const QModelIndex &) const { return COL_COUNT; }

QVariant TrafficModel::data(const QModelIndex &index, int role) const
{
    if (!index.isValid() || index.row() >= m_data.size()) return {};
    const TrafficEntry &e = m_data.at(index.row());

    if (role == Qt::DisplayRole) {
        switch (index.column()) {
        case COL_PROCESS:  return e.process;
        case COL_DOMAIN:   return (e.domain.isEmpty() || e.domain == "-") ? e.destIp : e.domain;
        case COL_PROTO:    return e.protocol;
        case COL_STATE:    return e.stateString();
        case COL_SRC:      return QString("%1:%2").arg(e.srcIp).arg(e.srcPort);
        case COL_DEST:     return QString("%1:%2").arg(e.destIp).arg(e.destPort);
        case COL_RATE_OUT: return e.formatRate(e.rateOutBps);
        case COL_RATE_IN:  return e.formatRate(e.rateInBps);
        case COL_BYTES:    return e.formatBytes(e.bytesOut + e.bytesIn);
        case COL_DURATION: return e.durationString();
        case COL_PID:      return e.pid;
        default: return {};
        }
    }

    if (role == Qt::ForegroundRole) {
        if (e.isClosed()) return QBrush(clrMuted());
        switch (index.column()) {
        case COL_DOMAIN:   return QBrush(clrLink());
        case COL_STATE:    return QBrush(forState(e.stateString()));
        case COL_RATE_OUT:
        case COL_RATE_IN:
            return QBrush((e.rateOutBps > 0 || e.rateInBps > 0) ? clrPrimary() : clrMuted());
        default:           return QBrush(clrPrimary());
        }
    }

    if (role == Qt::BackgroundRole) {
        if (e.isClosed()) return QBrush(clrBgBase());
        return {};
    }

    // Sparkline data — used by SparklineDelegate on IN column
    if (role == Qt::UserRole + 1 && index.column() == COL_RATE_IN) {
        QVector<quint32> hist = e.histIn.ordered();
        return QVariant::fromValue(hist);
    }
    if (role == Qt::UserRole + 1 && index.column() == COL_RATE_OUT) {
        QVector<quint32> hist = e.histOut.ordered();
        return QVariant::fromValue(hist);
    }

    if (role == Qt::TextAlignmentRole) {
        switch (index.column()) {
        case COL_RATE_OUT: case COL_RATE_IN: case COL_BYTES:
        case COL_DURATION: case COL_PID:
            return QVariant(int(Qt::AlignRight | Qt::AlignVCenter));
        default:
            return QVariant(int(Qt::AlignLeft | Qt::AlignVCenter));
        }
    }

    if (role == Qt::FontRole) {
        QFont f("Monospace", 11);
        f.setPixelSize(12);
        return f;
    }

    return {};
}

QVariant TrafficModel::headerData(int section, Qt::Orientation orientation, int role) const
{
    if (orientation != Qt::Horizontal || role != Qt::DisplayRole) return {};
    switch (section) {
    case COL_PROCESS:  return "PROCESS";
    case COL_DOMAIN:   return "DOMAIN / IP";
    case COL_PROTO:    return "PROTO";
    case COL_STATE:    return "STATE";
    case COL_SRC:      return "SOURCE";
    case COL_DEST:     return "DESTINATION";
    case COL_RATE_OUT: return "OUT";
    case COL_RATE_IN:  return "IN";
    case COL_BYTES:    return "TOTAL";
    case COL_DURATION: return "DURATION";
    case COL_PID:      return "PID";
    default:           return {};
    }
}

Qt::ItemFlags TrafficModel::flags(const QModelIndex &index) const
{
    if (!index.isValid()) return Qt::NoItemFlags;
    return Qt::ItemIsEnabled | Qt::ItemIsSelectable;
}

void TrafficModel::updateData(const QVector<TrafficEntry> &entries)
{
    beginResetModel();
    m_data = entries;
    endResetModel();
}

const TrafficEntry &TrafficModel::entryAt(int row) const { return m_data.at(row); }
