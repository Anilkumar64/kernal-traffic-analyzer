/**
 * @file ConnectionsTab.h
 * @brief Live connections tab widget.
 * @details Provides filters, table delegates, and context actions for active network connections.
 * @author Kernel Traffic Analyzer Project
 * @license MIT
 */
#pragma once

#include "models/TrafficModel.h"

#include <QSet>
#include <QWidget>

class QComboBox;
class QLineEdit;
class QTableView;

/**
 * @brief Widget showing active connection rows.
 */
class ConnectionsTab : public QWidget {
    Q_OBJECT

public:
    /** @brief Constructs the tab. @param parent Optional parent. */
    explicit ConnectionsTab(QWidget* parent = nullptr);
    /** @brief Updates connection data. @param records Connection records. */
    void setConnections(const QVector<ConnectionRecord>& records);

private slots:
    /** @brief Clears all filters. */
    void clearFilters();
    /** @brief Applies current filters to the model. */
    void applyFilters();
    /** @brief Shows a context menu for a table row. @param pos View-local position. */
    void showContextMenu(const QPoint& pos);

private:
    /** @brief Builds widgets and layout. */
    void setupUi();
    /** @brief Requests traceroute for an IP. @param ip Destination IP. */
    void requestTraceroute(const QString& ip);

    TrafficModel* traffic_model_{nullptr};
    QLineEdit* filter_edit_{nullptr};
    QComboBox* proto_combo_{nullptr};
    QComboBox* state_combo_{nullptr};
    QTableView* table_{nullptr};
    QSet<int> whitelisted_pids_;
};
