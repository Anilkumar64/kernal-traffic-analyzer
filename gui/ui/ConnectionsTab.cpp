#include "ConnectionsTab.h"
#include "Style.h"
#include "SparklineDelegate.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QFrame>

// ================================================================
// DetailPanel
// ================================================================
DetailPanel::DetailPanel(QWidget *parent) : QWidget(parent)
{
    setObjectName("DetailPanel");
    setFixedHeight(150);

    auto *layout = new QVBoxLayout(this);
    layout->setContentsMargins(16, 10, 16, 10);
    layout->setSpacing(8);

    m_process = new QLabel("", this);
    m_process->setStyleSheet(
        "color:#ffffff;font-size:15px;font-weight:600;font-family:'Segoe UI','Ubuntu',Arial,sans-serif;");
    layout->addWidget(m_process);

    auto *statsRow = new QHBoxLayout();
    statsRow->setSpacing(8);

    auto makeCard = [&](const QString &label, QLabel *&val)
    {
        auto *card = new QWidget(this);
        card->setObjectName("StatCard");
        card->setFixedHeight(68);
        card->setMinimumWidth(110);
        auto *cl = new QVBoxLayout(card);
        cl->setContentsMargins(16, 10, 16, 10);
        cl->setSpacing(2);
        auto *lbl = new QLabel(label, card);
        lbl->setStyleSheet(
            "color:#8a8a8a;font-size:14px;letter-spacing:1px;font-family:'Segoe UI','Ubuntu',Arial,sans-serif;");
        val = new QLabel("-", card);
        val->setStyleSheet(
            "color:#cccccc;font-size:22px;font-weight:600;font-family:'Segoe UI','Ubuntu',Arial,sans-serif;");
        cl->addWidget(lbl);
        cl->addWidget(val);
        statsRow->addWidget(card);
    };

    makeCard("OUT RATE", m_statOut);
    makeCard("IN RATE", m_statIn);
    makeCard("TOTAL", m_statBytes);
    makeCard("DURATION", m_statDuration);

    m_domain = new QLabel("", this);
    m_domain->setStyleSheet("color:#6366f1;font-size:13px;font-family:'Segoe UI','Ubuntu',Arial,sans-serif;");
    m_route = new QLabel("", this);
    m_route->setStyleSheet("color:#8a8a8a;font-size:10px;font-family:'Segoe UI','Ubuntu',Arial,sans-serif;");

    auto *infoRow = new QHBoxLayout();
    infoRow->addWidget(m_domain);
    infoRow->addSpacing(16);
    infoRow->addWidget(m_route);
    infoRow->addStretch();

    layout->addLayout(statsRow);
    layout->addLayout(infoRow);

    hide();
}

void DetailPanel::showEntry(const TrafficEntry &e)
{
    m_process->setText(
        QString("%1  (PID %2)  |  %3")
            .arg(e.process)
            .arg(e.pid)
            .arg(e.stateString()));
    m_statOut->setText(e.formatRate(e.rateOutBps));
    m_statIn->setText(e.formatRate(e.rateInBps));
    m_statBytes->setText(e.formatBytes(e.bytesOut + e.bytesIn));
    m_statDuration->setText(e.durationString());
    QString dom = (e.domain.isEmpty() || e.domain == "-") ? e.destIp : e.domain;
    m_domain->setText(dom + ":" + QString::number(e.destPort));
    m_route->setText(
        QString("SRC %1:%2  ->  DST %3:%4")
            .arg(e.srcIp)
            .arg(e.srcPort)
            .arg(e.destIp)
            .arg(e.destPort));
    show();
}

void DetailPanel::clear() { hide(); }

// ================================================================
// ConnectionsTab
// ================================================================
ConnectionsTab::ConnectionsTab(QWidget *parent) : QWidget(parent)
{
    auto *outerLayout = new QVBoxLayout(this);
    outerLayout->setContentsMargins(0, 0, 0, 0);
    outerLayout->setSpacing(0);

    // Top bar
    auto *topBar = new QWidget(this);
    topBar->setObjectName("TopBar");
    topBar->setFixedHeight(64);
    auto *tl = new QHBoxLayout(topBar);
    tl->setContentsMargins(20, 0, 20, 0);
    tl->setSpacing(12);

    auto *titleLbl = new QLabel("Live Connections", topBar);
    titleLbl->setStyleSheet(
        "color:#ffffff;font-size:16px;font-weight:600;font-family:'Segoe UI','Ubuntu',Arial,sans-serif;");
    m_countLabel = new QLabel("", topBar);
    m_countLabel->setStyleSheet("color:#8a8a8a;font-size:13px;font-family:'Segoe UI','Ubuntu',Arial,sans-serif;");
    tl->addWidget(titleLbl);
    tl->addWidget(m_countLabel);
    tl->addStretch();

    m_stateFilter = new QComboBox(topBar);
    m_stateFilter->addItems({"All states", "ESTABLISHED", "SYN_SENT",
                             "FIN_WAIT", "CLOSED", "UDP_ACTIVE"});
    connect(m_stateFilter, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, &ConnectionsTab::onStateFilterChanged);
    tl->addWidget(m_stateFilter);

    m_filterEdit = new QLineEdit(topBar);
    m_filterEdit->setPlaceholderText("Filter by process, domain, IP...");
    m_filterEdit->setFixedWidth(250);
    m_filterEdit->setClearButtonEnabled(true);
    connect(m_filterEdit, &QLineEdit::textChanged,
            this, &ConnectionsTab::onFilterChanged);
    tl->addWidget(m_filterEdit);

    outerLayout->addWidget(topBar);

    auto *div = new QFrame(this);
    div->setFrameShape(QFrame::HLine);
    div->setStyleSheet("background:#3e3e42;max-height:1px;");
    outerLayout->addWidget(div);

    // Splitter: table on top, detail panel below
    m_splitter = new QSplitter(Qt::Vertical, this);
    m_splitter->setHandleWidth(1);

    // Table
    m_model = new TrafficModel(this);
    m_proxy = new QSortFilterProxyModel(this);
    m_proxy->setSourceModel(m_model);
    m_proxy->setFilterCaseSensitivity(Qt::CaseInsensitive);
    m_proxy->setFilterKeyColumn(-1);

    m_table = new QTableView(this);
    m_table->setModel(m_proxy);
    m_table->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_table->setSelectionMode(QAbstractItemView::SingleSelection);
    m_table->setAlternatingRowColors(true);
    m_table->setSortingEnabled(true);
    m_table->setShowGrid(false);
    m_table->setWordWrap(false);
    m_table->verticalHeader()->setVisible(false);
    m_table->verticalHeader()->setDefaultSectionSize(48);
    m_table->horizontalHeader()->setSectionResizeMode(QHeaderView::Interactive);
    m_table->horizontalHeader()->setStretchLastSection(false);

    m_table->setColumnWidth(TrafficModel::COL_PROCESS, 130);
    m_table->setColumnWidth(TrafficModel::COL_DOMAIN, 190);
    m_table->setColumnWidth(TrafficModel::COL_PROTO, 55);
    m_table->setColumnWidth(TrafficModel::COL_STATE, 110);
    m_table->setColumnWidth(TrafficModel::COL_SRC, 145);
    m_table->setColumnWidth(TrafficModel::COL_DEST, 145);
    m_table->setColumnWidth(TrafficModel::COL_RATE_OUT, 85);
    m_table->setColumnWidth(TrafficModel::COL_RATE_IN, 85);
    m_table->setColumnWidth(TrafficModel::COL_BYTES, 85);
    m_table->setColumnWidth(TrafficModel::COL_DURATION, 80);
    m_table->setColumnWidth(TrafficModel::COL_PID, 55);
    m_table->sortByColumn(TrafficModel::COL_RATE_IN, Qt::DescendingOrder);
    m_table->verticalHeader()->setDefaultSectionSize(48); // taller rows for sparkline

    // Install sparkline delegate on IN and OUT rate columns
    auto *sparkIn = new SparklineDelegate(m_table);
    auto *sparkOut = new SparklineDelegate(m_table);
    m_table->setItemDelegateForColumn(TrafficModel::COL_RATE_IN, sparkIn);
    m_table->setItemDelegateForColumn(TrafficModel::COL_RATE_OUT, sparkOut);

    connect(m_table, &QTableView::clicked,
            this, &ConnectionsTab::onRowClicked);

    // Detail panel
    m_detail = new DetailPanel(this);

    m_splitter->addWidget(m_table);
    m_splitter->addWidget(m_detail);
    m_splitter->setStretchFactor(0, 1);
    m_splitter->setStretchFactor(1, 0);
    m_splitter->setSizes({10000, 0});

    outerLayout->addWidget(m_splitter, 1);
}

void ConnectionsTab::updateData(const QVector<TrafficEntry> &entries)
{
    m_model->updateData(entries);
    m_countLabel->setText(QString("  %1 connections").arg(entries.size()));
}

void ConnectionsTab::onRowClicked(const QModelIndex &index)
{
    if (!index.isValid())
        return;
    QModelIndex src = m_proxy->mapToSource(index);
    if (!src.isValid() || src.row() < 0 || src.row() >= m_model->rowCount())
        return;
    const TrafficEntry &e = m_model->entryAt(src.row());
    m_detail->showEntry(e);
    m_splitter->setSizes({10000, 150});
    emit processClicked(e.pid, e.process);
}

void ConnectionsTab::onFilterChanged(const QString &text)
{
    m_proxy->setFilterKeyColumn(-1);
    m_proxy->setFilterFixedString(text);
}

void ConnectionsTab::onStateFilterChanged(int idx)
{
    if (idx == 0)
    {
        m_proxy->setFilterKeyColumn(-1);
        m_proxy->setFilterFixedString(m_filterEdit->text());
    }
    else
    {
        m_proxy->setFilterKeyColumn(TrafficModel::COL_STATE);
        m_proxy->setFilterFixedString(m_stateFilter->itemText(idx));
    }
}
