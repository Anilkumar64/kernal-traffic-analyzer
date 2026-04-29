/**
 * @file ProcessesTab.cpp
 * @brief Implementation of the process aggregate tab.
 * @details Creates the process filter, table view, stacked percentage delegate, and expandable process rows.
 * @author Kernel Traffic Analyzer Project
 * @license MIT
 */
#include "tabs/ProcessesTab.h"

#include "delegates/PerfBarDelegate.h"
#include "delegates/RateBarDelegate.h"

#include <QHeaderView>
#include <QLineEdit>
#include <QTableView>
#include <QVBoxLayout>

ProcessesTab::ProcessesTab(QWidget* parent)
    : QWidget(parent)
{
    setupUi();
}

void ProcessesTab::setProcesses(const QVector<ProcRecord>& procs, const QVector<ConnectionRecord>& connections)
{
    proc_model_->setConnections(connections);
    proc_model_->setData(procs);
}

void ProcessesTab::onRowClicked(const QModelIndex& index)
{
    if (!index.isValid()) {
        return;
    }
    const std::optional<int> pid = proc_model_->pidAt(index.row());
    if (!pid.has_value()) {
        return;
    }
    if (expanded_pids_.contains(pid.value())) {
        expanded_pids_.remove(pid.value());
    } else {
        expanded_pids_.insert(pid.value());
    }
    proc_model_->setExpandedPids(expanded_pids_);
}

void ProcessesTab::setupUi()
{
    auto* root = new QVBoxLayout(this);
    root->setContentsMargins(12, 12, 12, 12);
    root->setSpacing(10);

    filter_edit_ = new QLineEdit(this);
    filter_edit_->setPlaceholderText("Search process name or PID...");
    root->addWidget(filter_edit_);

    proc_model_ = new ProcModel(this);
    table_ = new QTableView(this);
    table_->setModel(proc_model_);
    table_->setItemDelegateForColumn(ProcModel::ColTcpPct, new PerfBarDelegate(ProcModel::ColTcpPct, ProcModel::ColUdpPct, table_));
    table_->setItemDelegateForColumn(ProcModel::ColUdpPct, new PerfBarDelegate(ProcModel::ColTcpPct, ProcModel::ColUdpPct, table_));
    table_->setItemDelegateForColumn(ProcModel::ColRateIn, new RateBarDelegate(table_));
    table_->setItemDelegateForColumn(ProcModel::ColRateOut, new RateBarDelegate(table_));
    table_->setSortingEnabled(true);
    table_->setAlternatingRowColors(true);
    table_->setSelectionBehavior(QAbstractItemView::SelectRows);
    table_->horizontalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
    table_->horizontalHeader()->setSectionResizeMode(ProcModel::ColTopRemotes, QHeaderView::Stretch);
    table_->verticalHeader()->hide();
    table_->verticalHeader()->setDefaultSectionSize(28);
    root->addWidget(table_, 1);

    connect(filter_edit_, &QLineEdit::textChanged, proc_model_, &ProcModel::filter);
    connect(table_, &QTableView::clicked, this, &ProcessesTab::onRowClicked);
}
