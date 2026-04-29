#include "AnomalyTab.h"
#include "../core/AnomalyModel.h"
#include <QApplication>
#include <QHeaderView>
#include <QLineEdit>
#include <QPushButton>
#include <QSortFilterProxyModel>
#include <QStyle>
#include <QSystemTrayIcon>
#include <QTableView>
#include <QVBoxLayout>

AnomalyTab::AnomalyTab(QWidget *parent) : QWidget(parent)
{
    auto *layout = new QVBoxLayout(this);
    auto *bar = new QWidget(this);
    auto *barLayout = new QHBoxLayout(bar);
    auto *filter = new QLineEdit(bar);
    filter->setPlaceholderText("Filter anomalies");
    auto *clear = new QPushButton("Clear", bar);
    barLayout->addWidget(filter, 1);
    barLayout->addWidget(clear);
    layout->addWidget(bar);

    m_model = new AnomalyModel(this);
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
    connect(clear, &QPushButton::clicked, m_model, &AnomalyModel::clear);
    m_tray = new QSystemTrayIcon(QApplication::style()->standardIcon(QStyle::SP_MessageBoxWarning), this);
    m_tray->setToolTip("Kernel Traffic Analyzer");
    m_tray->show();
}

void AnomalyTab::updateData(const QVector<AnomalyEntry> &entries)
{
    m_model->updateData(entries);
    if (entries.size() > m_lastCount && m_tray->isVisible())
        m_tray->showMessage("Kernel Traffic Analyzer", QString("%1 anomalies").arg(entries.size()));
    m_lastCount = entries.size();
    m_tray->setToolTip(QString("%1 anomalies").arg(entries.size()));
}

int AnomalyTab::count() const { return m_model->rowCount(); }
