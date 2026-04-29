#include "DnsTab.h"
#include "../core/DnsModel.h"
#include <QHeaderView>
#include <QLineEdit>
#include <QSortFilterProxyModel>
#include <QTableView>
#include <QVBoxLayout>

DnsTab::DnsTab(QWidget *parent) : QWidget(parent)
{
    auto *layout = new QVBoxLayout(this);
    auto *filter = new QLineEdit(this);
    filter->setPlaceholderText("Filter DNS");
    layout->addWidget(filter);
    m_model = new DnsModel(this);
    m_proxy = new QSortFilterProxyModel(this);
    m_proxy->setSourceModel(m_model);
    m_proxy->setFilterCaseSensitivity(Qt::CaseInsensitive);
    m_proxy->setFilterKeyColumn(-1);
    auto *table = new QTableView(this);
    table->setModel(m_proxy);
    table->setAlternatingRowColors(true);
    table->setShowGrid(false);
    table->verticalHeader()->setDefaultSectionSize(36);
    table->verticalHeader()->hide();
    table->horizontalHeader()->setSectionResizeMode(QHeaderView::Interactive);
    table->setSortingEnabled(true);
    layout->addWidget(table, 1);
    connect(filter, &QLineEdit::textChanged, m_proxy, &QSortFilterProxyModel::setFilterFixedString);
}

void DnsTab::updateData(const QVector<DnsEntry> &entries) { m_model->updateData(entries); }
