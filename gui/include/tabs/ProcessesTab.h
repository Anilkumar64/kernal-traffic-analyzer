/**
 * @file ProcessesTab.h
 * @brief Process aggregate tab widget.
 * @details Displays per-process connection totals with live filtering, protocol bars, and expandable remote details.
 * @author Kernel Traffic Analyzer Project
 * @license MIT
 */
#pragma once

#include "models/ProcModel.h"

#include <QSet>
#include <QWidget>

class QLineEdit;
class QTableView;

/**
 * @brief Widget showing process aggregate rows.
 */
class ProcessesTab : public QWidget {
    Q_OBJECT

public:
    /** @brief Constructs the tab. @param parent Optional parent. */
    explicit ProcessesTab(QWidget* parent = nullptr);
    /** @brief Updates process and connection data. @param procs Process records. @param connections Connection records. */
    void setProcesses(const QVector<ProcRecord>& procs, const QVector<ConnectionRecord>& connections);

private slots:
    /** @brief Toggles expansion for clicked process rows. @param index Clicked index. */
    void onRowClicked(const QModelIndex& index);

private:
    /** @brief Builds widgets and layout. */
    void setupUi();

    ProcModel* proc_model_{nullptr};
    QLineEdit* filter_edit_{nullptr};
    QTableView* table_{nullptr};
    QSet<int> expanded_pids_;
};
