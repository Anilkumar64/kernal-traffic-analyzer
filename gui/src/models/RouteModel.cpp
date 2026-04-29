/**
 * @file RouteModel.cpp
 * @brief Implementation of the traceroute tree model.
 * @details Groups hop records by target IP and presents target rows with expandable hop children.
 * @author Kernel Traffic Analyzer Project
 * @license MIT
 */
#include "models/RouteModel.h"

#include <QBrush>
#include <QHash>

RouteModel::RouteModel(QObject* parent)
    : QAbstractItemModel(parent)
{
}

QModelIndex RouteModel::index(int row, int column, const QModelIndex& parentIndex) const
{
    if (row < 0 || column < 0 || column >= ColumnCount) {
        return {};
    }

    if (!parentIndex.isValid()) {
        if (row >= static_cast<int>(roots_.size())) {
            return {};
        }
        return createIndex(row, column, roots_.at(static_cast<size_t>(row)).get());
    }

    RouteNode* parentNode = nodeFor(parentIndex);
    if (parentNode == nullptr || row >= static_cast<int>(parentNode->children.size())) {
        return {};
    }
    return createIndex(row, column, parentNode->children.at(static_cast<size_t>(row)).get());
}

QModelIndex RouteModel::parent(const QModelIndex& child) const
{
    if (!child.isValid()) {
        return {};
    }
    RouteNode* node = nodeFor(child);
    if (node == nullptr || node->parent == nullptr) {
        return {};
    }
    return createIndex(rowForNode(node->parent), 0, node->parent);
}

int RouteModel::rowCount(const QModelIndex& parentIndex) const
{
    if (!parentIndex.isValid()) {
        return static_cast<int>(roots_.size());
    }
    RouteNode* node = nodeFor(parentIndex);
    return node == nullptr ? 0 : static_cast<int>(node->children.size());
}

int RouteModel::columnCount(const QModelIndex& parent) const
{
    Q_UNUSED(parent)
    return ColumnCount;
}

QVariant RouteModel::data(const QModelIndex& modelIndex, int role) const
{
    if (!modelIndex.isValid()) {
        return {};
    }
    const RouteNode* node = nodeFor(modelIndex);
    if (node == nullptr) {
        return {};
    }
    const RouteRecord& rec = node->record;
    if (role == Qt::DisplayRole) {
        if (node->isTarget) {
            switch (modelIndex.column()) {
            case ColTargetHop: return rec.targetIp;
            case ColDomain: return rec.domain;
            default: return {};
            }
        }
        switch (modelIndex.column()) {
        case ColTargetHop: return QString("Hop %1").arg(rec.hopNum);
        case ColDomain: return rec.domain;
        case ColHopNum: return rec.hopNum;
        case ColHopIp: return rec.hopIp;
        case ColRtt: return QString::number(rec.rttMs, 'f', 2);
        case ColCountry: return rec.country;
        case ColAsn: return rec.asn;
        case ColOrg: return rec.org;
        default: return {};
        }
    }
    if (role == Qt::ForegroundRole && !node->isTarget) {
        return QBrush(QColor("#8b949e"));
    }
    if (role == Qt::TextAlignmentRole && (modelIndex.column() == ColHopNum || modelIndex.column() == ColRtt)) {
        return Qt::AlignVCenter | Qt::AlignRight;
    }
    return {};
}

QVariant RouteModel::headerData(int section, Qt::Orientation orientation, int role) const
{
    if (orientation != Qt::Horizontal || role != Qt::DisplayRole) {
        return {};
    }
    static const QStringList headers = {"Target/Hop", "Domain", "Hop#", "Hop IP", "RTT ms", "Country", "ASN", "Org"};
    return headers.value(section);
}

void RouteModel::setData(const QVector<RouteRecord>& records)
{
    beginResetModel();
    roots_.clear();
    QHash<QString, RouteNode*> targetNodes;
    for (const RouteRecord& rec : records) {
        RouteNode* target = targetNodes.value(rec.targetIp, nullptr);
        if (target == nullptr) {
            auto root = std::make_unique<RouteNode>();
            root->record.targetIp = rec.targetIp;
            root->record.domain = rec.domain;
            root->isTarget = true;
            target = root.get();
            targetNodes.insert(rec.targetIp, target);
            roots_.push_back(std::move(root));
        }
        auto hop = std::make_unique<RouteNode>();
        hop->record = rec;
        hop->parent = target;
        hop->isTarget = false;
        target->children.push_back(std::move(hop));
    }
    endResetModel();
}

RouteModel::RouteNode* RouteModel::nodeFor(const QModelIndex& index) const
{
    if (!index.isValid()) {
        return nullptr;
    }
    return static_cast<RouteNode*>(index.internalPointer());
}

int RouteModel::rowForNode(const RouteNode* node) const
{
    if (node == nullptr) {
        return 0;
    }
    if (node->parent == nullptr) {
        for (size_t i = 0; i < roots_.size(); ++i) {
            if (roots_.at(i).get() == node) {
                return static_cast<int>(i);
            }
        }
        return 0;
    }
    const std::vector<std::unique_ptr<RouteNode>>& siblings = node->parent->children;
    for (size_t i = 0; i < siblings.size(); ++i) {
        if (siblings.at(i).get() == node) {
            return static_cast<int>(i);
        }
    }
    return 0;
}
