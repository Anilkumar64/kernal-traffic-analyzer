/**
 * @file RoutesTab.h
 * @brief Traceroute route tab widget.
 * @details Displays route targets and hops in a tree and lets users request new IPv4 traceroutes.
 * @author Kernel Traffic Analyzer Project
 * @license MIT
 */
#pragma once

#include "models/RouteModel.h"

#include <QWidget>

class QLineEdit;
class QTreeView;

/**
 * @brief Widget showing traceroute data.
 */
class RoutesTab : public QWidget {
    Q_OBJECT

public:
    /** @brief Constructs the tab. @param parent Optional parent. */
    explicit RoutesTab(QWidget* parent = nullptr);
    /** @brief Updates route records. @param records Route records. */
    void setRoutes(const QVector<RouteRecord>& records);

private slots:
    /** @brief Validates and submits a traceroute request. */
    void requestTraceroute();

private:
    /** @brief Builds widgets and layout. */
    void setupUi();

    RouteModel* route_model_{nullptr};
    QLineEdit* ip_edit_{nullptr};
    QTreeView* tree_{nullptr};
};
