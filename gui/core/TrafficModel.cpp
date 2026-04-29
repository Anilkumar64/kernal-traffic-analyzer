#include "TrafficModel.h"
#include "../ui/Style.h"
#include <QBrush>
#include <QFont>

static QColor stateColor(const TrafficEntry &e)
{
    if (e.state == ConnState::Established) return KtaColors::Teal;
    if (e.state == ConnState::UdpActive) return KtaColors::Accent;
    if (e.state == ConnState::SynSent || e.state == ConnState::SynRecv) return KtaColors::Amber;
    return KtaColors::Text4;
}

TrafficModel::TrafficModel(QObject *parent) : QAbstractTableModel(parent) {}
int TrafficModel::rowCount(const QModelIndex &) const { return m_data.size(); }
int TrafficModel::columnCount(const QModelIndex &) const { return Count; }

QVariant TrafficModel::data(const QModelIndex &index, int role) const
{
    if (!index.isValid() || index.row() >= m_data.size()) return {};
    const auto &e = m_data.at(index.row());
    if (role == Qt::DisplayRole) {
        switch (index.column()) {
        case Pid: return e.pid;
        case Process: return e.process;
        case Protocol: return e.protocol;
        case Local: return QString("%1:%2").arg(e.srcIp).arg(e.srcPort);
        case Remote: return QString("%1:%2").arg(e.destIp).arg(e.destPort);
        case Domain: return e.domain == "-" ? QString() : e.domain;
        case State: return e.stateString();
        case InBytes: return e.formatBytes(e.bytesIn);
        case OutBytes: return e.formatBytes(e.bytesOut);
        case InRate: return e.formatRate(e.rateInBps);
        case OutRate: return e.formatRate(e.rateOutBps);
        default: return {};
        }
    }
    if (role == Qt::ForegroundRole && index.column() == State) return QBrush(stateColor(e));
    if (role == Qt::TextAlignmentRole && index.column() >= InBytes) return int(Qt::AlignRight | Qt::AlignVCenter);
    if (role == Qt::FontRole && (index.column() == Local || index.column() == Remote || index.column() >= InBytes)) {
        QFont font;
        font.setFamilies({"JetBrains Mono", "Consolas", "Ubuntu Mono"});
        font.setPixelSize(12);
        return font;
    }
    return {};
}

QVariant TrafficModel::headerData(int section, Qt::Orientation orientation, int role) const
{
    if (orientation != Qt::Horizontal || role != Qt::DisplayRole) return {};
    static const QStringList headers = {"PID", "PROCESS", "PROTO", "LOCAL IP:PORT", "REMOTE IP:PORT",
                                        "DOMAIN", "STATE", "IN (BYTES)", "OUT (BYTES)", "IN RATE", "OUT RATE"};
    return headers.value(section);
}

void TrafficModel::updateData(const QVector<TrafficEntry> &entries)
{
    beginResetModel();
    m_data = entries;
    endResetModel();
}

const TrafficEntry &TrafficModel::entryAt(int row) const { return m_data.at(row); }
