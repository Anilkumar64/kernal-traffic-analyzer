/**
 * @file RouteModel.h
 * @brief Tree model for traceroute target and hop records.
 * @details Groups route hop rows by target IP and exposes them to a QTreeView with top-level target rows and child hop rows.
 * @author Kernel Traffic Analyzer Project
 * @license MIT
 */
#pragma once

#include "ProcReader.h"

#include <QAbstractItemModel>
#include <memory>
#include <vector>

/**
 * @brief Qt tree model for traceroute data.
 */
class RouteModel : public QAbstractItemModel {
    Q_OBJECT

public:
    /** @brief Route tree columns. */
    enum Column { ColTargetHop = 0, ColDomain, ColHopNum, ColHopIp, ColRtt, ColCountry, ColAsn, ColOrg, ColumnCount };

    /** @brief Constructs the model. @param parent Optional parent. */
    explicit RouteModel(QObject* parent = nullptr);
    /** @brief Creates an index for row and column. @param row Row. @param column Column. @param parent Parent index. @return Model index. */
    QModelIndex index(int row, int column, const QModelIndex& parent = QModelIndex()) const override;
    /** @brief Returns the parent index. @param child Child index. @return Parent index. */
    QModelIndex parent(const QModelIndex& child) const override;
    /** @brief Returns row count. @param parent Parent index. @return Row count. */
    int rowCount(const QModelIndex& parent = QModelIndex()) const override;
    /** @brief Returns column count. @param parent Parent index. @return Column count. */
    int columnCount(const QModelIndex& parent = QModelIndex()) const override;
    /** @brief Returns data for a tree cell. @param index Model index. @param role Data role. @return Cell data. */
    QVariant data(const QModelIndex& index, int role = Qt::DisplayRole) const override;
    /** @brief Returns header data. @param section Header section. @param orientation Orientation. @param role Role. @return Header text. */
    QVariant headerData(int section, Qt::Orientation orientation, int role = Qt::DisplayRole) const override;

public slots:
    /** @brief Rebuilds the route tree. @param records Route records. */
    void setData(const QVector<RouteRecord>& records);

private:
    /** @brief Internal route tree node. */
    struct RouteNode {
        RouteRecord record;
        RouteNode* parent{nullptr};
        std::vector<std::unique_ptr<RouteNode>> children;
        bool isTarget{false};
    };

    /** @brief Returns a node from an index. @param index Model index. @return Node pointer or null. */
    RouteNode* nodeFor(const QModelIndex& index) const;
    /** @brief Returns row number for a node within its parent. @param node Node. @return Row index. */
    int rowForNode(const RouteNode* node) const;

    std::vector<std::unique_ptr<RouteNode>> roots_;
};
