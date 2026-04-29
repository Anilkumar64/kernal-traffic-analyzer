#include "DnsTab.h"
#include "../core/DnsModel.h"
#include <QClipboard>
#include <QGuiApplication>
#include <QHeaderView>
#include <QLineEdit>
#include <QMenu>
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
    table->setContextMenuPolicy(Qt::CustomContextMenu);
    connect(table, &QTableView::customContextMenuRequested, this, [this, table](const QPoint &pos) {
        const auto idx = table->indexAt(pos);
        if (!idx.isValid()) return;
        QMenu menu(this);
        auto *copyRow = menu.addAction("Copy Row");
        auto *copyIp = menu.addAction("Copy IP");
        auto *copyProc = menu.addAction("Copy Process Name");
        auto *chosen = menu.exec(table->viewport()->mapToGlobal(pos));
        if (!chosen) return;
        QString text;
        if (chosen == copyRow) {
            for (int c = 0; c < m_proxy->columnCount(); ++c) text += m_proxy->index(idx.row(), c).data().toString() + '\t';
        } else if (chosen == copyIp) {
            text = m_proxy->index(idx.row(), DnsModel::Ip).data().toString();
        }
        QGuiApplication::clipboard()->setText(text.trimmed());
    });
}

void DnsTab::updateData(const QVector<DnsEntry> &entries) { m_model->updateData(entries); }
