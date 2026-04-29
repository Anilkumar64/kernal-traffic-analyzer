/**
 * @file AnomalyTab.cpp
 * @brief Implementation of the active anomalies tab.
 * @details Builds the anomaly table, acknowledgement context menu, and clear acknowledged action.
 * @author Kernel Traffic Analyzer Project
 * @license MIT
 */
#include "tabs/AnomalyTab.h"

#include <QHeaderView>
#include <QHBoxLayout>
#include <QLabel>
#include <QMenu>
#include <QPushButton>
#include <QSpacerItem>
#include <QTableView>
#include <QVBoxLayout>

AnomalyTab::AnomalyTab(QWidget* parent)
    : QWidget(parent)
{
    setupUi();
}

void AnomalyTab::setAnomalies(const QVector<AnomalyRecord>& records)
{
    anomaly_model_->setData(records);
    emitCriticalState();
}

void AnomalyTab::clearAcknowledged()
{
    anomaly_model_->clearAcknowledged();
    emitCriticalState();
}

void AnomalyTab::showContextMenu(const QPoint& pos)
{
    const QModelIndex index = table_->indexAt(pos);
    if (!index.isValid()) {
        return;
    }
    QMenu menu(this);
    QAction* acknowledge = menu.addAction("Acknowledge");
    QAction* chosen = menu.exec(table_->viewport()->mapToGlobal(pos));
    if (chosen == acknowledge) {
        anomaly_model_->acknowledgeRow(index.row());
        emitCriticalState();
    }
}

void AnomalyTab::setupUi()
{
    auto* root = new QVBoxLayout(this);
    root->setContentsMargins(12, 12, 12, 12);
    root->setSpacing(10);

    auto* header = new QHBoxLayout();
    auto* title = new QLabel("Active Anomalies", this);
    auto* clearButton = new QPushButton("Clear Acknowledged", this);
    clearButton->setProperty("class", "secondary");
    header->addWidget(title);
    header->addStretch(1);
    header->addWidget(clearButton);
    root->addLayout(header);

    anomaly_model_ = new AnomalyModel(this);
    table_ = new QTableView(this);
    table_->setModel(anomaly_model_);
    table_->setSortingEnabled(true);
    table_->setAlternatingRowColors(true);
    table_->setSelectionBehavior(QAbstractItemView::SelectRows);
    table_->setContextMenuPolicy(Qt::CustomContextMenu);
    table_->horizontalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
    table_->horizontalHeader()->setSectionResizeMode(AnomalyModel::ColDescription, QHeaderView::Stretch);
    table_->verticalHeader()->hide();
    table_->verticalHeader()->setDefaultSectionSize(28);
    root->addWidget(table_, 1);

    connect(clearButton, &QPushButton::clicked, this, &AnomalyTab::clearAcknowledged);
    connect(table_, &QTableView::customContextMenuRequested, this, &AnomalyTab::showContextMenu);
}

void AnomalyTab::emitCriticalState()
{
    emit criticalAnomalyActive(anomaly_model_->hasCriticalActive());
}
