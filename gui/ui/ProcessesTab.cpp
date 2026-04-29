#include "ProcessesTab.h"
#include "../core/ProcModel.h"
#include <QClipboard>
#include <QGuiApplication>
#include <QHeaderView>
#include <QLabel>
#include <QLineEdit>
#include <QMenu>
#include <QSortFilterProxyModel>
#include <QTableView>
#include <QVBoxLayout>

ProcessesTab::ProcessesTab(QWidget *parent) : QWidget(parent)
{
    auto *layout = new QVBoxLayout(this);
    m_filter = new QLineEdit(this);
    m_filter->setPlaceholderText("Filter processes");
    layout->addWidget(m_filter);
    m_model = new ProcModel(this);
    m_proxy = new QSortFilterProxyModel(this);
    m_proxy->setSourceModel(m_model);
    m_proxy->setFilterCaseSensitivity(Qt::CaseInsensitive);
    m_proxy->setFilterKeyColumn(-1);
    m_table = new QTableView(this);
    m_table->setModel(m_proxy);
    m_table->setAlternatingRowColors(true);
    m_table->setShowGrid(false);
    m_table->verticalHeader()->setDefaultSectionSize(36);
    m_table->verticalHeader()->hide();
    m_table->setSortingEnabled(true);
    m_table->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_table->horizontalHeader()->setSectionResizeMode(QHeaderView::Interactive);
    layout->addWidget(m_table, 1);
    m_detail = new QLabel(this);
    m_detail->setFrameShape(QFrame::StyledPanel);
    m_detail->setWordWrap(true);
    m_detail->hide();
    layout->addWidget(m_detail);
    connect(m_filter, &QLineEdit::textChanged, m_proxy, &QSortFilterProxyModel::setFilterFixedString);
    connect(m_table, &QTableView::clicked, this, &ProcessesTab::showDetails);
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
        } else if (chosen == copyProc) {
            text = m_proxy->index(idx.row(), ProcModel::Process).data().toString();
        }
        QGuiApplication::clipboard()->setText(text.trimmed());
    });
}

void ProcessesTab::updateData(const QVector<ProcEntry> &processes, const QVector<TrafficEntry> &connections)
{
    m_connections = connections;
    m_model->updateData(processes);
}

void ProcessesTab::showDetails(const QModelIndex &index)
{
    const auto source = m_proxy->mapToSource(index);
    if (!source.isValid()) return;
    const auto &proc = m_model->entryAt(source.row());
    QStringList rows;
    for (const auto &conn : m_connections) {
        if (conn.pid == proc.pid)
            rows << QString("%1 %2:%3 -> %4:%5 %6").arg(conn.protocol, conn.srcIp).arg(conn.srcPort).arg(conn.destIp).arg(conn.destPort).arg(conn.stateString());
    }
    m_detail->setText(rows.isEmpty() ? "No current connections for this process." : rows.join("\n"));
    m_detail->show();
}
