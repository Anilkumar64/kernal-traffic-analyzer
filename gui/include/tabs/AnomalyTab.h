/**
 * @file AnomalyTab.h
 * @brief Active anomalies tab widget.
 * @details Displays live anomaly rows, acknowledgement context actions, and emits critical-state changes for sidebar blinking.
 * @author Kernel Traffic Analyzer Project
 * @license MIT
 */
#pragma once

#include "models/AnomalyModel.h"

#include <QWidget>

class QTableView;

/**
 * @brief Widget showing active anomalies.
 */
class AnomalyTab : public QWidget {
    Q_OBJECT

public:
    /** @brief Constructs the tab. @param parent Optional parent. */
    explicit AnomalyTab(QWidget* parent = nullptr);
    /** @brief Updates anomaly records. @param records Anomaly records. */
    void setAnomalies(const QVector<AnomalyRecord>& records);

signals:
    /** @brief Reports whether a critical unacknowledged anomaly is active. @param active True when active. */
    void criticalAnomalyActive(bool active);

private slots:
    /** @brief Clears acknowledged anomalies from the model. */
    void clearAcknowledged();
    /** @brief Shows acknowledgement menu. @param pos View-local position. */
    void showContextMenu(const QPoint& pos);

private:
    /** @brief Builds widgets and layout. */
    void setupUi();
    /** @brief Emits current critical state. */
    void emitCriticalState();

    AnomalyModel* anomaly_model_{nullptr};
    QTableView* table_{nullptr};
};
