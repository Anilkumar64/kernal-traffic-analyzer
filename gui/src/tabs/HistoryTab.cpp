/**
 * @file HistoryTab.cpp
 * @brief Implementation of the snapshot history tab.
 * @details Uses HistoryDB to load metadata ranges, delete snapshots, and export selected snapshot JSON documents.
 * @author Kernel Traffic Analyzer Project
 * @license MIT
 */
#include "tabs/HistoryTab.h"

#include <QDateTimeEdit>
#include <QFile>
#include <QFileDialog>
#include <QHeaderView>
#include <QHBoxLayout>
#include <QItemSelectionModel>
#include <QLabel>
#include <QMessageBox>
#include <QPushButton>
#include <QStandardItemModel>
#include <QTableView>
#include <QTextStream>
#include <QVBoxLayout>

HistoryTab::HistoryTab(QWidget* parent)
    : QWidget(parent)
{
    setupUi();
}

void HistoryTab::setHistoryDB(HistoryDB* db)
{
    history_db_ = db;
    loadRange();
}

void HistoryTab::loadRange()
{
    model_->removeRows(0, model_->rowCount());
    if (history_db_ == nullptr) {
        return;
    }
    const QVector<SnapshotMeta> rows = history_db_->queryRange(from_edit_->dateTime(), to_edit_->dateTime());
    for (const SnapshotMeta& meta : rows) {
        QList<QStandardItem*> items;
        auto* idItem = new QStandardItem(QString::number(meta.id));
        idItem->setData(meta.id, Qt::UserRole);
        items << idItem
              << new QStandardItem(QString::number(meta.sessionId))
              << new QStandardItem(meta.timestamp.toLocalTime().toString(Qt::ISODate));
        model_->appendRow(items);
    }
    table_->resizeColumnsToContents();
}

void HistoryTab::deleteSelected()
{
    if (history_db_ == nullptr) {
        return;
    }
    const std::optional<int> id = selectedSnapshotId();
    if (!id.has_value()) {
        return;
    }
    const QMessageBox::StandardButton confirm = QMessageBox::question(this, "Delete Snapshot", QString("Delete snapshot %1?").arg(id.value()));
    if (confirm != QMessageBox::Yes) {
        return;
    }
    history_db_->deleteSnapshot(id.value());
    loadRange();
}

void HistoryTab::exportSelected()
{
    if (history_db_ == nullptr) {
        return;
    }
    const std::optional<int> id = selectedSnapshotId();
    if (!id.has_value()) {
        return;
    }
    const QString json = history_db_->getSnapshotJson(id.value());
    if (json.isEmpty()) {
        QMessageBox::warning(this, "Export Failed", "Could not load the selected snapshot.");
        return;
    }
    const QString path = QFileDialog::getSaveFileName(this, "Export Snapshot", QString("snapshot-%1.json").arg(id.value()), "JSON Files (*.json)");
    if (path.isEmpty()) {
        return;
    }
    QFile file(path);
    if (!file.open(QIODevice::WriteOnly | QIODevice::Text | QIODevice::Truncate)) {
        QMessageBox::warning(this, "Export Failed", "Could not write the selected snapshot.");
        return;
    }
    QTextStream out(&file);
    out << json;
}

void HistoryTab::updateDetails()
{
    if (history_db_ == nullptr) {
        details_->setText("No history database opened.");
        return;
    }
    const std::optional<int> id = selectedSnapshotId();
    if (!id.has_value()) {
        details_->setText("Select a snapshot to inspect its stored JSON payload.");
        return;
    }
    const QString json = history_db_->getSnapshotJson(id.value());
    details_->setText(json.left(1500));
}

void HistoryTab::setupUi()
{
    auto* root = new QVBoxLayout(this);
    root->setContentsMargins(12, 12, 12, 12);
    root->setSpacing(10);

    auto* controls = new QHBoxLayout();
    from_edit_ = new QDateTimeEdit(QDateTime::currentDateTime().addDays(-1), this);
    to_edit_ = new QDateTimeEdit(QDateTime::currentDateTime().addSecs(3600), this);
    from_edit_->setCalendarPopup(true);
    to_edit_->setCalendarPopup(true);
    auto* loadButton = new QPushButton("Load Range", this);
    auto* deleteButton = new QPushButton("Delete Selected", this);
    deleteButton->setProperty("class", "danger");
    auto* exportButton = new QPushButton("Export Selected", this);
    exportButton->setProperty("class", "secondary");
    controls->addWidget(new QLabel("From:", this));
    controls->addWidget(from_edit_);
    controls->addWidget(new QLabel("To:", this));
    controls->addWidget(to_edit_);
    controls->addWidget(loadButton);
    controls->addStretch(1);
    controls->addWidget(deleteButton);
    controls->addWidget(exportButton);
    root->addLayout(controls);

    model_ = new QStandardItemModel(this);
    model_->setHorizontalHeaderLabels({"ID", "Session", "Timestamp"});
    table_ = new QTableView(this);
    table_->setModel(model_);
    table_->setSelectionBehavior(QAbstractItemView::SelectRows);
    table_->setSelectionMode(QAbstractItemView::SingleSelection);
    table_->setAlternatingRowColors(true);
    table_->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
    table_->verticalHeader()->hide();
    root->addWidget(table_, 1);

    details_ = new QLabel("Select a snapshot to inspect its stored JSON payload.", this);
    details_->setTextInteractionFlags(Qt::TextSelectableByMouse);
    details_->setWordWrap(true);
    details_->setMinimumHeight(120);
    details_->setAlignment(Qt::AlignTop | Qt::AlignLeft);
    root->addWidget(details_);

    connect(loadButton, &QPushButton::clicked, this, &HistoryTab::loadRange);
    connect(deleteButton, &QPushButton::clicked, this, &HistoryTab::deleteSelected);
    connect(exportButton, &QPushButton::clicked, this, &HistoryTab::exportSelected);
    connect(table_->selectionModel(), &QItemSelectionModel::selectionChanged, this, &HistoryTab::updateDetails);
}

std::optional<int> HistoryTab::selectedSnapshotId() const
{
    if (table_->selectionModel() == nullptr) {
        return std::nullopt;
    }
    const QModelIndexList rows = table_->selectionModel()->selectedRows();
    if (rows.isEmpty()) {
        return std::nullopt;
    }
    const QModelIndex idIndex = rows.first().sibling(rows.first().row(), 0);
    const QVariant value = idIndex.data(Qt::UserRole);
    if (!value.canConvert<int>()) {
        return std::nullopt;
    }
    return value.toInt();
}
