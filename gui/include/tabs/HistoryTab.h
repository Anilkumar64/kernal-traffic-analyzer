/**
 * @file HistoryTab.h
 * @brief Snapshot history tab widget.
 * @details Loads stored SQLite snapshot metadata, shows snapshot details, deletes rows, and exports selected JSON snapshots.
 * @author Kernel Traffic Analyzer Project
 * @license MIT
 */
#pragma once

#include "HistoryDB.h"

#include <QWidget>

class QDateTimeEdit;
class QLabel;
class QStandardItemModel;
class QTableView;

/**
 * @brief Widget for historical snapshots.
 */
class HistoryTab : public QWidget {
    Q_OBJECT

public:
    /** @brief Constructs the tab. @param parent Optional parent. */
    explicit HistoryTab(QWidget* parent = nullptr);
    /** @brief Assigns the history database. @param db Non-owning database pointer. */
    void setHistoryDB(HistoryDB* db);

private slots:
    /** @brief Loads snapshots in the selected date range. */
    void loadRange();
    /** @brief Deletes the selected snapshot after confirmation. */
    void deleteSelected();
    /** @brief Exports selected snapshot JSON. */
    void exportSelected();
    /** @brief Updates detail text for current selection. */
    void updateDetails();

private:
    /** @brief Builds widgets and layout. */
    void setupUi();
    /** @brief Returns selected snapshot ID if one is selected. @return Snapshot ID or empty optional. */
    std::optional<int> selectedSnapshotId() const;

    HistoryDB* history_db_{nullptr};
    QDateTimeEdit* from_edit_{nullptr};
    QDateTimeEdit* to_edit_{nullptr};
    QTableView* table_{nullptr};
    QLabel* details_{nullptr};
    QStandardItemModel* model_{nullptr};
};
