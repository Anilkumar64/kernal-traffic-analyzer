#include "ProcModel.h"
#include <QBrush>
#include <QFont>

static QColor clrPrimary() { return QColor("#e6edf3"); }
static QColor clrMuted()   { return QColor("#484f58"); }
static QColor clrLink()    { return QColor("#58a6ff"); }
static QColor clrDanger()  { return QColor("#f85149"); }
static QColor clrDangerBg(){ return QColor("#2d1117"); }

ProcModel::ProcModel(QObject *parent) : QAbstractTableModel(parent) {}
int ProcModel::rowCount(const QModelIndex &) const { return m_data.size(); }
int ProcModel::columnCount(const QModelIndex &) const { return COL_COUNT; }

QVariant ProcModel::data(const QModelIndex &index, int role) const
{
    if (!index.isValid() || index.row() >= m_data.size()) return {};
    const ProcEntry &e = m_data.at(index.row());

    if (role == Qt::DisplayRole) {
        switch (index.column()) {
        case COL_PROCESS:  return e.process;
        case COL_EXE:      return e.exeShort();
        case COL_CONNS:    return QString("TCP:%1  UDP:%2").arg(e.tcpConns).arg(e.udpConns);
        case COL_RATE_OUT: return e.formatRate(e.rateOutBps);
        case COL_RATE_IN:  return e.formatRate(e.rateInBps);
        case COL_BYTES:    return e.formatBytes(e.bytesOut + e.bytesIn);
        case COL_TCP_PCT:  return QString("%1%").arg(e.tcpPct);
        case COL_ANOMALY:  return e.anomalyStr;
        case COL_TOP_DEST: return e.topConns.isEmpty() ? "-" : e.topConns[0].domain;
        case COL_PID:      return e.pid;
        default: return {};
        }
    }

    if (role == Qt::ForegroundRole) {
        switch (index.column()) {
        case COL_ANOMALY:
            return QBrush(e.hasAnomaly() ? clrDanger() : clrMuted());
        case COL_RATE_OUT: case COL_RATE_IN:
            return QBrush((e.rateOutBps > 0 || e.rateInBps > 0) ? clrPrimary() : clrMuted());
        case COL_TOP_DEST: return QBrush(clrLink());
        default:           return QBrush(clrPrimary());
        }
    }

    if (role == Qt::BackgroundRole) {
        if (e.hasAnomaly()) return QBrush(clrDangerBg());
        return {};
    }

    if (role == Qt::TextAlignmentRole) {
        switch (index.column()) {
        case COL_RATE_OUT: case COL_RATE_IN: case COL_BYTES:
        case COL_TCP_PCT:  case COL_PID:
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

QVariant ProcModel::headerData(int section, Qt::Orientation orientation, int role) const
{
    if (orientation != Qt::Horizontal || role != Qt::DisplayRole) return {};
    switch (section) {
    case COL_PROCESS:  return "PROCESS";
    case COL_EXE:      return "EXECUTABLE";
    case COL_CONNS:    return "CONNECTIONS";
    case COL_RATE_OUT: return "OUT";
    case COL_RATE_IN:  return "IN";
    case COL_BYTES:    return "TOTAL";
    case COL_TCP_PCT:  return "TCP%";
    case COL_ANOMALY:  return "ANOMALY";
    case COL_TOP_DEST: return "TOP DEST";
    case COL_PID:      return "PID";
    default:           return {};
    }
}

Qt::ItemFlags ProcModel::flags(const QModelIndex &index) const
{
    if (!index.isValid()) return Qt::NoItemFlags;
    return Qt::ItemIsEnabled | Qt::ItemIsSelectable;
}

void ProcModel::updateData(const QVector<ProcEntry> &entries)
{
    beginResetModel();
    m_data = entries;
    endResetModel();
}

const ProcEntry &ProcModel::entryAt(int row) const { return m_data.at(row); }
