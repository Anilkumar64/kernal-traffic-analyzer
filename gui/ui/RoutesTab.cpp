#include "RoutesTab.h"
#include "../core/RouteModel.h"
#include <QClipboard>
#include <QGuiApplication>
#include <QHeaderView>
#include <QLineEdit>
#include <QMenu>
#include <QSortFilterProxyModel>
#include <QSplitter>
#include <QTableView>
#include <QVBoxLayout>

RoutesTab::RoutesTab(QWidget *parent) : QWidget(parent)
{
    auto *layout = new QVBoxLayout(this);
    auto *filter = new QLineEdit(this);
    filter->setPlaceholderText("Filter routes");
    layout->addWidget(filter);
    auto *splitter = new QSplitter(Qt::Vertical, this);
    m_model = new RouteModel(this);
    m_hopModel = new RouteHopModel(this);
    m_proxy = new QSortFilterProxyModel(this);
    m_proxy->setSourceModel(m_model);
    m_proxy->setFilterCaseSensitivity(Qt::CaseInsensitive);
    m_proxy->setFilterKeyColumn(-1);
    m_table = new QTableView(splitter);
    auto *hopTable = new QTableView(splitter);
    m_table->setModel(m_proxy);
    hopTable->setModel(m_hopModel);
    for (auto *table : {m_table, hopTable}) {
        table->setAlternatingRowColors(true);
        table->setShowGrid(false);
        table->verticalHeader()->setDefaultSectionSize(36);
        table->verticalHeader()->hide();
        table->horizontalHeader()->setSectionResizeMode(QHeaderView::Interactive);
        table->setSortingEnabled(true);
        table->setSelectionBehavior(QAbstractItemView::SelectRows);
    }
    splitter->addWidget(m_table);
    splitter->addWidget(hopTable);
    layout->addWidget(splitter, 1);
    connect(filter, &QLineEdit::textChanged, m_proxy, &QSortFilterProxyModel::setFilterFixedString);
    connect(m_table, &QTableView::clicked, this, &RoutesTab::selectRoute);
    m_table->setContextMenuPolicy(Qt::CustomContextMenu);
    connect(m_table, &QTableView::customContextMenuRequested, this, [this](const QPoint &pos) {
        const auto idx = m_table->indexAt(pos);
        if (!idx.isValid()) return;
        QMenu menu(this);
        auto *copyRow = menu.addAction("Copy Row");
        auto *copyIp = menu.addAction("Copy IP");
        auto *copyProc = menu.addAction("Copy Process Name");
        auto *chosen = menu.exec(m_table->viewport()->mapToGlobal(pos));
        if (!chosen) return;
        QString text;
        if (chosen == copyRow) {
            for (int c = 0; c < m_proxy->columnCount(); ++c) text += m_proxy->index(idx.row(), c).data().toString() + '\t';
        } else if (chosen == copyIp) {
            text = m_proxy->index(idx.row(), RouteModel::Destination).data().toString();
        }
        QGuiApplication::clipboard()->setText(text.trimmed());
    });
}

void RoutesTab::updateData(const QVector<RouteEntry> &entries) { m_model->updateData(entries); }

void RoutesTab::selectRoute(const QModelIndex &index)
{
    const auto source = m_proxy->mapToSource(index);
    if (source.isValid()) m_hopModel->updateData(m_model->entryAt(source.row()).hops);
}
