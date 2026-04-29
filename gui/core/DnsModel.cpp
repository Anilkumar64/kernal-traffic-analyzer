#include "DnsModel.h"
#include <QDateTime>
#include <QFont>

DnsModel::DnsModel(QObject *parent) : QAbstractTableModel(parent) {}
int DnsModel::rowCount(const QModelIndex &) const { return m_data.size(); }
int DnsModel::columnCount(const QModelIndex &) const { return Count; }

QVariant DnsModel::data(const QModelIndex &index, int role) const
{
    if (!index.isValid() || index.row() >= m_data.size()) return {};
    const auto &e = m_data.at(index.row());
    auto ts = [](qint64 value) { return value > 0 ? QDateTime::fromSecsSinceEpoch(value).toString("yyyy-MM-dd hh:mm:ss") : QString(); };
    if (role == Qt::DisplayRole) {
        switch (index.column()) {
        case Ip: return e.ip;
        case Domain: return e.domain;
        case Ttl: return e.ttlString();
        case FirstSeen: return ts(e.firstSeen);
        case LastSeen: return ts(e.lastSeen);
        case QueryCount: return e.queryCount;
        default: return {};
        }
    }
    if (role == Qt::TextAlignmentRole && (index.column() == Ttl || index.column() == QueryCount)) return int(Qt::AlignRight | Qt::AlignVCenter);
    if (role == Qt::FontRole && index.column() == Ip) {
        QFont font;
        font.setFamilies({"JetBrains Mono", "Consolas", "Ubuntu Mono"});
        font.setPixelSize(12);
        return font;
    }
    return {};
}

QVariant DnsModel::headerData(int section, Qt::Orientation orientation, int role) const
{
    if (orientation != Qt::Horizontal || role != Qt::DisplayRole) return {};
    static const QStringList headers = {"IP ADDRESS", "DOMAIN", "TTL", "FIRST SEEN", "LAST SEEN", "QUERIES"};
    return headers.value(section);
}

void DnsModel::updateData(const QVector<DnsEntry> &entries)
{
    beginResetModel();
    m_data = entries;
    endResetModel();
}
