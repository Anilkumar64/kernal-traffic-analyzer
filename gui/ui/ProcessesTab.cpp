#include "ProcessesTab.h"
#include "Style.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QFrame>

ProcessesTab::ProcessesTab(QWidget *parent) : QWidget(parent)
{
    auto *outerLayout = new QVBoxLayout(this);
    outerLayout->setContentsMargins(0, 0, 0, 0);
    outerLayout->setSpacing(0);

    // Top bar
    auto *topBar = new QWidget(this);
    topBar->setObjectName("TopBar");
    topBar->setFixedHeight(52);
    auto *tl = new QHBoxLayout(topBar);
    tl->setContentsMargins(16, 0, 16, 0);
    tl->setSpacing(12);

    auto *titleLbl = new QLabel("Processes", topBar);
    titleLbl->setStyleSheet(
        "color:#e6edf3;font-size:14px;font-weight:600;font-family:Monospace;");
    m_countLabel = new QLabel("", topBar);
    m_countLabel->setStyleSheet("color:#484f58;font-size:11px;font-family:Monospace;");
    tl->addWidget(titleLbl);
    tl->addWidget(m_countLabel);
    tl->addStretch();

    m_filterEdit = new QLineEdit(topBar);
    m_filterEdit->setPlaceholderText("Filter by process or path...");
    m_filterEdit->setFixedWidth(240);
    m_filterEdit->setClearButtonEnabled(true);
    connect(m_filterEdit, &QLineEdit::textChanged,
            this, &ProcessesTab::onFilterChanged);
    tl->addWidget(m_filterEdit);

    outerLayout->addWidget(topBar);

    auto *div = new QFrame(this);
    div->setFrameShape(QFrame::HLine);
    div->setStyleSheet("background:#30363d;max-height:1px;");
    outerLayout->addWidget(div);

    // Model + proxy
    m_model = new ProcModel(this);
    m_proxy = new QSortFilterProxyModel(this);
    m_proxy->setSourceModel(m_model);
    m_proxy->setFilterCaseSensitivity(Qt::CaseInsensitive);
    m_proxy->setFilterKeyColumn(-1);

    // Table
    m_table = new QTableView(this);
    m_table->setModel(m_proxy);
    m_table->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_table->setSelectionMode(QAbstractItemView::SingleSelection);
    m_table->setAlternatingRowColors(true);
    m_table->setSortingEnabled(true);
    m_table->setShowGrid(false);
    m_table->setWordWrap(false);
    m_table->verticalHeader()->setVisible(false);
    m_table->verticalHeader()->setDefaultSectionSize(34);
    m_table->horizontalHeader()->setSectionResizeMode(QHeaderView::Interactive);
    m_table->horizontalHeader()->setStretchLastSection(false);

    m_table->setColumnWidth(ProcModel::COL_PROCESS, 130);
    m_table->setColumnWidth(ProcModel::COL_EXE, 210);
    m_table->setColumnWidth(ProcModel::COL_CONNS, 140);
    m_table->setColumnWidth(ProcModel::COL_RATE_OUT, 88);
    m_table->setColumnWidth(ProcModel::COL_RATE_IN, 88);
    m_table->setColumnWidth(ProcModel::COL_BYTES, 88);
    m_table->setColumnWidth(ProcModel::COL_TCP_PCT, 58);
    m_table->setColumnWidth(ProcModel::COL_ANOMALY, 110);
    m_table->setColumnWidth(ProcModel::COL_TOP_DEST, 190);
    m_table->setColumnWidth(ProcModel::COL_PID, 55);
    m_table->sortByColumn(ProcModel::COL_RATE_IN, Qt::DescendingOrder);

    connect(m_table, &QTableView::clicked,
            this, &ProcessesTab::onRowClicked);

    outerLayout->addWidget(m_table, 1);
}

void ProcessesTab::updateData(const QVector<ProcEntry> &entries)
{
    m_model->updateData(entries);
    m_countLabel->setText(QString("  %1 processes").arg(entries.size()));
}

void ProcessesTab::onRowClicked(const QModelIndex &index)
{
    if (!index.isValid())
        return;
    QModelIndex src = m_proxy->mapToSource(index);
    if (!src.isValid() || src.row() < 0 || src.row() >= m_model->rowCount())
        return;
    const ProcEntry &e = m_model->entryAt(src.row());
    emit processClicked(e.pid, e.process, e.exe);
}

void ProcessesTab::onFilterChanged(const QString &text)
{
    m_proxy->setFilterFixedString(text);
}
