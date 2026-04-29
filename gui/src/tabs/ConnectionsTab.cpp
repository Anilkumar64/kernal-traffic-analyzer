/**
 * @file ConnectionsTab.cpp
 * @brief Implementation of the live connections tab.
 * @details Creates filters, table delegates, and context actions for killing, copying, traceroute, and in-memory whitelisting.
 * @author Kernel Traffic Analyzer Project
 * @license MIT
 */
#include "tabs/ConnectionsTab.h"

#include "delegates/ProtoBadgeDelegate.h"
#include "delegates/RateBarDelegate.h"
#include "delegates/StateBadgeDelegate.h"

#include <QApplication>
#include <QClipboard>
#include <QComboBox>
#include <QFile>
#include <QHeaderView>
#include <QHBoxLayout>
#include <QLineEdit>
#include <QMenu>
#include <QMessageBox>
#include <QPushButton>
#include <QTableView>
#include <QVBoxLayout>
#include <csignal>
#include <unistd.h>

ConnectionsTab::ConnectionsTab(QWidget* parent)
    : QWidget(parent)
{
    setupUi();
}

void ConnectionsTab::setConnections(const QVector<ConnectionRecord>& records)
{
    traffic_model_->setData(records);
}

void ConnectionsTab::clearFilters()
{
    filter_edit_->clear();
    proto_combo_->setCurrentIndex(0);
    state_combo_->setCurrentIndex(0);
    applyFilters();
}

void ConnectionsTab::applyFilters()
{
    traffic_model_->filter(filter_edit_->text());
    traffic_model_->setProtocolFilter(proto_combo_->currentText());
    traffic_model_->setStateFilter(state_combo_->currentText());
}

void ConnectionsTab::showContextMenu(const QPoint& pos)
{
    const QModelIndex index = table_->indexAt(pos);
    if (!index.isValid()) {
        return;
    }
    const std::optional<ConnectionRecord> rec = traffic_model_->recordAt(index.row());
    if (!rec.has_value()) {
        return;
    }

    QMenu menu(this);
    QAction* killAction = menu.addAction(QString("Kill Process (PID %1)").arg(rec->pid));
    QAction* copyAction = menu.addAction("Copy Row");
    QAction* traceAction = menu.addAction("Request Traceroute");
    QAction* whitelistAction = menu.addAction("Add to Whitelist");
    QAction* chosen = menu.exec(table_->viewport()->mapToGlobal(pos));
    if (chosen == nullptr) {
        return;
    }
    if (chosen == killAction) {
        const QMessageBox::StandardButton confirm = QMessageBox::question(this, "Kill Process", QString("Send SIGTERM to PID %1?").arg(rec->pid));
        if (confirm == QMessageBox::Yes) {
            ::kill(rec->pid, SIGTERM);
        }
    } else if (chosen == copyAction) {
        QApplication::clipboard()->setText(traffic_model_->rowToPipe(index.row()));
    } else if (chosen == traceAction) {
        requestTraceroute(rec->dstIp);
    } else if (chosen == whitelistAction) {
        whitelisted_pids_.insert(rec->pid);
        traffic_model_->setWhitelistedPids(whitelisted_pids_);
    }
}

void ConnectionsTab::setupUi()
{
    auto* root = new QVBoxLayout(this);
    root->setContentsMargins(12, 12, 12, 12);
    root->setSpacing(10);

    auto* filterRow = new QHBoxLayout();
    filter_edit_ = new QLineEdit(this);
    filter_edit_->setPlaceholderText("Search PID, process, IP, domain...");
    proto_combo_ = new QComboBox(this);
    proto_combo_->addItems({"All", "TCP", "UDP", "ICMP"});
    state_combo_ = new QComboBox(this);
    state_combo_->addItems({"All", "ESTABLISHED", "SYN", "CLOSED", "FIN_WAIT"});
    auto* clearButton = new QPushButton("Clear", this);
    clearButton->setProperty("class", "secondary");
    filterRow->addWidget(filter_edit_, 1);
    filterRow->addWidget(proto_combo_);
    filterRow->addWidget(state_combo_);
    filterRow->addWidget(clearButton);
    root->addLayout(filterRow);

    traffic_model_ = new TrafficModel(this);
    table_ = new QTableView(this);
    table_->setModel(traffic_model_);
    table_->setItemDelegateForColumn(TrafficModel::ColState, new StateBadgeDelegate(table_));
    table_->setItemDelegateForColumn(TrafficModel::ColProto, new ProtoBadgeDelegate(table_));
    table_->setItemDelegateForColumn(TrafficModel::ColRateIn, new RateBarDelegate(table_));
    table_->setItemDelegateForColumn(TrafficModel::ColRateOut, new RateBarDelegate(table_));
    table_->setSortingEnabled(true);
    table_->setSelectionBehavior(QAbstractItemView::SelectRows);
    table_->setSelectionMode(QAbstractItemView::SingleSelection);
    table_->setContextMenuPolicy(Qt::CustomContextMenu);
    table_->horizontalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
    table_->horizontalHeader()->setSectionResizeMode(TrafficModel::ColDomain, QHeaderView::Stretch);
    table_->verticalHeader()->hide();
    table_->verticalHeader()->setDefaultSectionSize(28);
    table_->setShowGrid(false);
    table_->setAlternatingRowColors(true);
    root->addWidget(table_, 1);

    connect(filter_edit_, &QLineEdit::textChanged, this, &ConnectionsTab::applyFilters);
    connect(proto_combo_, &QComboBox::currentTextChanged, this, &ConnectionsTab::applyFilters);
    connect(state_combo_, &QComboBox::currentTextChanged, this, &ConnectionsTab::applyFilters);
    connect(clearButton, &QPushButton::clicked, this, &ConnectionsTab::clearFilters);
    connect(table_, &QTableView::customContextMenuRequested, this, &ConnectionsTab::showContextMenu);
}

void ConnectionsTab::requestTraceroute(const QString& ip)
{
    QFile file("/proc/traffic_analyzer_routes_pending");
    if (!file.open(QIODevice::WriteOnly | QIODevice::Append | QIODevice::Text)) {
        QMessageBox::warning(this, "Traceroute Failed", "Could not write traceroute request.");
        return;
    }
    file.write(QString("%1\n").arg(ip).toUtf8());
}
