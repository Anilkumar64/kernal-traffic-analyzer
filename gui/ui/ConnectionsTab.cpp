#include "ConnectionsTab.h"
#include "../core/TrafficModel.h"
#include <QCheckBox>
#include <QGuiApplication>
#include <QHeaderView>
#include <QLineEdit>
#include <QMenu>
#include <QSortFilterProxyModel>
#include <QTableView>
#include <QVBoxLayout>
#include <QClipboard>

class ConnectionProxy : public QSortFilterProxyModel {
public:
    bool showInactive = false;
protected:
    bool filterAcceptsRow(int row, const QModelIndex &parent) const override {
        if (!QSortFilterProxyModel::filterAcceptsRow(row, parent)) return false;
        if (showInactive) return true;
        auto state = sourceModel()->index(row, TrafficModel::State, parent).data().toString();
        return state != "CLOSED" && state != "FIN_WAIT";
    }
};

static void setupTable(QTableView *table)
{
    table->setAlternatingRowColors(true);
    table->setShowGrid(false);
    table->verticalHeader()->setDefaultSectionSize(36);
    table->verticalHeader()->hide();
    table->horizontalHeader()->setSectionsClickable(true);
    table->horizontalHeader()->setSectionResizeMode(QHeaderView::Interactive);
    table->setSortingEnabled(true);
    table->setSelectionBehavior(QAbstractItemView::SelectRows);
}

ConnectionsTab::ConnectionsTab(QWidget *parent) : QWidget(parent)
{
    auto *layout = new QVBoxLayout(this);
    auto *bar = new QWidget(this);
    auto *barLayout = new QHBoxLayout(bar);
    m_filter = new QLineEdit(bar);
    m_filter->setPlaceholderText("Filter connections");
    m_showInactive = new QCheckBox("Show inactive", bar);
    barLayout->addWidget(m_filter, 1);
    barLayout->addWidget(m_showInactive);
    layout->addWidget(bar);

    m_model = new TrafficModel(this);
    m_proxy = new ConnectionProxy;
    m_proxy->setParent(this);
    m_proxy->setSourceModel(m_model);
    m_proxy->setFilterCaseSensitivity(Qt::CaseInsensitive);
    m_proxy->setFilterKeyColumn(-1);
    m_table = new QTableView(this);
    setupTable(m_table);
    m_table->setModel(m_proxy);
    layout->addWidget(m_table, 1);
    connect(m_filter, &QLineEdit::textChanged, m_proxy, &QSortFilterProxyModel::setFilterFixedString);
    connect(m_showInactive, &QCheckBox::toggled, this, [this](bool on) {
        static_cast<ConnectionProxy *>(m_proxy)->showInactive = on;
        m_proxy->invalidate();
    });
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
            text = m_proxy->index(idx.row(), TrafficModel::Remote).data().toString();
        } else if (chosen == copyProc) {
            text = m_proxy->index(idx.row(), TrafficModel::Process).data().toString();
        }
        QGuiApplication::clipboard()->setText(text.trimmed());
    });
}

void ConnectionsTab::updateData(const QVector<TrafficEntry> &entries) { m_model->updateData(entries); }
