/**
 * @file DnsTab.h
 * @brief DNS cache tab widget.
 * @details Displays DNS resolution history with a live domain/IP filter.
 * @author Kernel Traffic Analyzer Project
 * @license MIT
 */
#pragma once

#include "models/DnsModel.h"

#include <QWidget>

class QLineEdit;
class QTableView;

/**
 * @brief Widget showing DNS records.
 */
class DnsTab : public QWidget {
    Q_OBJECT

public:
    /** @brief Constructs the tab. @param parent Optional parent. */
    explicit DnsTab(QWidget* parent = nullptr);
    /** @brief Updates DNS records. @param records DNS records. */
    void setDns(const QVector<DnsRecord>& records);

private:
    /** @brief Builds widgets and layout. */
    void setupUi();

    DnsModel* dns_model_{nullptr};
    QLineEdit* filter_edit_{nullptr};
    QTableView* table_{nullptr};
};
