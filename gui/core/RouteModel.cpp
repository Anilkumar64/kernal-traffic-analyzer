#include "RouteModel.h"
#include <QDateTime>
#include <QFont>

RouteModel::RouteModel(QObject *parent) : QAbstractTableModel(parent) {}
int RouteModel::rowCount(const QModelIndex &) const { return m_data.size(); }
int RouteModel::columnCount(const QModelIndex &) const { return Count; }
QVariant RouteModel::data(const QModelIndex &index, int role) const
{
    if (!index.isValid() || index.row() >= m_data.size()) return {};
    const auto &e = m_data.at(index.row());
    if (role == Qt::DisplayRole) {
        switch (index.column()) {
        case Destination: return e.destIp;
        case Domain: return e.domain == "-" ? QString() : e.domain;
        case Hops: return e.totalHops;
        case LastTraced: return e.lastTraced > 0 ? QDateTime::fromSecsSinceEpoch(e.lastTraced).toString("yyyy-MM-dd hh:mm:ss") : QString();
        default: return {};
        }
    }
    if (role == Qt::FontRole && index.column() == Destination) {
        QFont font;
        font.setFamilies({"JetBrains Mono", "Consolas", "Ubuntu Mono"});
        font.setPixelSize(12);
        return font;
    }
    return {};
}
QVariant RouteModel::headerData(int section, Qt::Orientation orientation, int role) const
{
    if (orientation != Qt::Horizontal || role != Qt::DisplayRole) return {};
    static const QStringList headers = {"DESTINATION IP", "DOMAIN", "HOPS", "LAST TRACED"};
    return headers.value(section);
}
void RouteModel::updateData(const QVector<RouteEntry> &entries) { beginResetModel(); m_data = entries; endResetModel(); }
const RouteEntry &RouteModel::entryAt(int row) const { return m_data.at(row); }

RouteHopModel::RouteHopModel(QObject *parent) : QAbstractTableModel(parent) {}
int RouteHopModel::rowCount(const QModelIndex &) const { return m_data.size(); }
int RouteHopModel::columnCount(const QModelIndex &) const { return Count; }
QVariant RouteHopModel::data(const QModelIndex &index, int role) const
{
    if (!index.isValid() || index.row() >= m_data.size()) return {};
    const auto &h = m_data.at(index.row());
    if (role == Qt::DisplayRole) {
        switch (index.column()) {
        case HopNumber: return h.hopN;
        case Ip: return h.hopIp == "0.0.0.0" || h.hopIp == "-" ? QString() : h.hopIp;
        case Rtt: return h.rttMs > 0 ? QString::number(h.rttMs, 'f', 1) : QString();
        case City: return h.city == "-" ? QString() : h.city;
        case Asn: return h.asn == "-" ? QString() : h.asn;
        default: return {};
        }
    }
    if (role == Qt::FontRole && (index.column() == Ip || index.column() == Rtt)) {
        QFont font;
        font.setFamilies({"JetBrains Mono", "Consolas", "Ubuntu Mono"});
        font.setPixelSize(12);
        return font;
    }
    return {};
}
QVariant RouteHopModel::headerData(int section, Qt::Orientation orientation, int role) const
{
    if (orientation != Qt::Horizontal || role != Qt::DisplayRole) return {};
    static const QStringList headers = {"HOP #", "IP", "RTT (MS)", "CITY", "ASN"};
    return headers.value(section);
}
void RouteHopModel::updateData(const QVector<RouteHop> &entries) { beginResetModel(); m_data = entries; endResetModel(); }
