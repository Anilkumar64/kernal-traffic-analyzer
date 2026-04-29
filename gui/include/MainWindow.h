/**
 * @file MainWindow.h
 * @brief Main desktop window for Kernel Traffic Analyzer.
 * @details Owns navigation, tab stack, threaded proc refresh, history autosave, status bar, export actions, and anomaly blinking state.
 * @author Kernel Traffic Analyzer Project
 * @license MIT
 */
#pragma once

#include "HistoryDB.h"
#include "ProcReader.h"

#include <QMainWindow>
#include <memory>

class AnomalyTab;
class ConnectionsTab;
class DnsTab;
class HistoryTab;
class NetworkPerfTab;
class ProcessesTab;
class QButtonGroup;
class QLabel;
class QStackedWidget;
class QTimer;
class QToolButton;
class RoutesTab;
class QGraphicsOpacityEffect;

/**
 * @brief Top-level KTA GUI window.
 */
class MainWindow : public QMainWindow {
    Q_OBJECT

public:
    /** @brief Constructs the main window. @param parent Optional parent. */
    explicit MainWindow(QWidget* parent = nullptr);
    /** @brief Ends history session and stops timers/readers. */
    ~MainWindow() override;

private slots:
    /** @brief Handles new parsed data. @param data Snapshot data. */
    void onDataReady(const ParsedData& data);
    /** @brief Handles missing kernel module state. */
    void onModuleNotLoaded();
    /** @brief Switches tabs from sidebar button ID. @param id Button ID. */
    void onNavButtonClicked(int id);
    /** @brief Requests a proc refresh. */
    void onRefreshTimer();
    /** @brief Saves the current snapshot. */
    void onAutoSave();
    /** @brief Toggles anomaly icon blink opacity. */
    void onBlinkTimer();
    /** @brief Exports JSON. */
    void onExportJson();
    /** @brief Exports CSV. */
    void onExportCsv();
    /** @brief Shows about dialog. */
    void onAbout();
    /** @brief Starts or stops anomaly blinking. @param active True when critical anomaly is active. */
    void onCriticalAnomalyActive(bool active);

private:
    /** @brief Builds the complete UI. */
    void setupUi();
    /** @brief Builds menu actions. */
    void setupMenuBar();
    /** @brief Builds sidebar navigation. */
    void setupSidebar();
    /** @brief Builds stacked tab widgets. */
    void setupStack();
    /** @brief Builds status bar labels. */
    void setupStatusBar();
    /** @brief Connects signals and timers. */
    void setupConnections();
    /** @brief Applies the resource stylesheet. */
    void applyStylesheet();
    /** @brief Updates status bar text. @param data Snapshot data. */
    void updateStatusBar(const ParsedData& data);

    QWidget* sidebar_{nullptr};
    QButtonGroup* nav_group_{nullptr};
    QToolButton* nav_buttons_[7]{};
    QStackedWidget* stack_{nullptr};
    ConnectionsTab* tab_connections_{nullptr};
    ProcessesTab* tab_processes_{nullptr};
    DnsTab* tab_dns_{nullptr};
    AnomalyTab* tab_anomaly_{nullptr};
    RoutesTab* tab_routes_{nullptr};
    HistoryTab* tab_history_{nullptr};
    NetworkPerfTab* tab_perf_{nullptr};
    std::unique_ptr<ProcReader> proc_reader_;
    std::unique_ptr<HistoryDB> history_db_;
    ParsedData current_data_;
    QLabel* status_module_{nullptr};
    QLabel* status_pkt_rate_{nullptr};
    QLabel* status_bytes_{nullptr};
    QLabel* status_uptime_{nullptr};
    QTimer* refresh_timer_{nullptr};
    QTimer* autosave_timer_{nullptr};
    QTimer* blink_timer_{nullptr};
    QGraphicsOpacityEffect* anomaly_effect_{nullptr};
    bool blink_state_{false};
};
