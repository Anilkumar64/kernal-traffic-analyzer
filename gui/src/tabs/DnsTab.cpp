/**
 * @file DnsTab.cpp
 * @brief Implementation of the DNS tab.
 * @details Creates a sortable DNS table with a live text filter for domains and IP addresses.
 * @author Kernel Traffic Analyzer Project
 * @license MIT
 */
#include "tabs/DnsTab.h"

#include <QHeaderView>
#include <QLineEdit>
#include <QTableView>
#include <QVBoxLayout>

DnsTab::DnsTab(QWidget* parent)
    : QWidget(parent)
{
    setupUi();
}

void DnsTab::setDns(const QVector<DnsRecord>& records)
{
    dns_model_->setData(records);
}

void DnsTab::setupUi()
{
    auto* root = new QVBoxLayout(this);
    root->setContentsMargins(12, 12, 12, 12);
    root->setSpacing(10);
    filter_edit_ = new QLineEdit(this);
    filter_edit_->setPlaceholderText("Search domain or IP...");
    root->addWidget(filter_edit_);

    dns_model_ = new DnsModel(this);
    table_ = new QTableView(this);
    table_->setModel(dns_model_);
    table_->setSortingEnabled(true);
    table_->setAlternatingRowColors(true);
    table_->setSelectionBehavior(QAbstractItemView::SelectRows);
    table_->horizontalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
    table_->horizontalHeader()->setSectionResizeMode(DnsModel::ColDomain, QHeaderView::Stretch);
    table_->verticalHeader()->hide();
    table_->verticalHeader()->setDefaultSectionSize(28);
    root->addWidget(table_, 1);

    connect(filter_edit_, &QLineEdit::textChanged, dns_model_, &DnsModel::filter);
}
