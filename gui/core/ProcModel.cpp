#include "ProcModel.h"
#include <QFont>

ProcModel::ProcModel(QObject *parent) : QAbstractTableModel(parent) {}
int ProcModel::rowCount(const QModelIndex &) const { return m_data.size(); }
int ProcModel::columnCount(const QModelIndex &) const { return Count; }

QVariant ProcModel::data(const QModelIndex &index, int role) const
{
    if (!index.isValid() || index.row() >= m_data.size()) return {};
    const auto &e = m_data.at(index.row());
    if (role == Qt::DisplayRole) {
        switch (index.column()) {
        case Pid: return e.pid;
        case Process: return e.process;
        case Exe: return e.exe;
        case Connections: return e.totalConns;
        case InTotal: return e.formatBytes(e.bytesIn);
        case OutTotal: return e.formatBytes(e.bytesOut);
        case InRate: return e.formatRate(e.rateInBps);
        case OutRate: return e.formatRate(e.rateOutBps);
        default: return {};
        }
    }
    if (role == Qt::TextAlignmentRole && index.column() >= Connections) return int(Qt::AlignRight | Qt::AlignVCenter);
    if (role == Qt::FontRole && index.column() >= InTotal) {
        QFont font;
        font.setFamilies({"JetBrains Mono", "Consolas", "Ubuntu Mono"});
        font.setPixelSize(12);
        return font;
    }
    return {};
}

QVariant ProcModel::headerData(int section, Qt::Orientation orientation, int role) const
{
    if (orientation != Qt::Horizontal || role != Qt::DisplayRole) return {};
    static const QStringList headers = {"PID", "PROCESS", "EXE PATH", "CONNECTIONS",
                                        "IN (TOTAL)", "OUT (TOTAL)", "IN RATE", "OUT RATE"};
    return headers.value(section);
}

void ProcModel::updateData(const QVector<ProcEntry> &entries)
{
    beginResetModel();
    m_data = entries;
    endResetModel();
}

const ProcEntry &ProcModel::entryAt(int row) const { return m_data.at(row); }
