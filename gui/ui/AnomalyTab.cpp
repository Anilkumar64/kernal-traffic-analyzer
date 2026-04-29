#include "AnomalyTab.h"
#include "Style.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QFrame>

AnomalyTab::AnomalyTab(QWidget *parent) : QWidget(parent)
{
    auto *outer = new QVBoxLayout(this);
    outer->setContentsMargins(0, 0, 0, 0);
    outer->setSpacing(0);

    // Top bar
    auto *topBar = new QWidget(this);
    topBar->setObjectName("TopBar");
    topBar->setFixedHeight(60);
    auto *tl = new QHBoxLayout(topBar);
    tl->setContentsMargins(20, 0, 20, 0);
    auto *title = new QLabel("Anomaly Monitor", topBar);
    title->setStyleSheet(
        "color:#ffffff;font-size:16px;font-weight:600;font-family:'Segoe UI','Ubuntu',Arial,sans-serif;");
    m_countLabel = new QLabel("", topBar);
    m_countLabel->setStyleSheet("color:#ef4444;font-size:11px;");
    tl->addWidget(title);
    tl->addWidget(m_countLabel);
    tl->addStretch();
    outer->addWidget(topBar);

    auto *div = new QFrame(this);
    div->setFrameShape(QFrame::HLine);
    div->setStyleSheet("background:#3e3e42;max-height:1px;");
    outer->addWidget(div);

    // No data label
    m_noDataLabel = new QLabel("No anomalies detected", this);
    m_noDataLabel->setAlignment(Qt::AlignCenter);
    m_noDataLabel->setStyleSheet("color:#8a8a8a;font-size:16px;font-family:'Segoe UI','Ubuntu',Arial,sans-serif;");

    // Table
    m_table = new QTableWidget(0, 8, this);
    m_table->setHorizontalHeaderLabels({
        "PROCESS", "EXE", "ANOMALY",
        "NEW CONNS/s", "PORTS/s",
        "TOTAL CONNS", "OUT", "IN"
    });
    m_table->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_table->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_table->setAlternatingRowColors(true);
    m_table->setShowGrid(false);
    m_table->verticalHeader()->setVisible(false);
    m_table->verticalHeader()->setDefaultSectionSize(42);
    m_table->horizontalHeader()->setSectionResizeMode(QHeaderView::Interactive);
    m_table->horizontalHeader()->setStretchLastSection(false);
    m_table->setColumnWidth(0, 120);
    m_table->setColumnWidth(1, 180);
    m_table->setColumnWidth(2, 110);
    m_table->setColumnWidth(3,  95);
    m_table->setColumnWidth(4,  80);
    m_table->setColumnWidth(5, 100);
    m_table->setColumnWidth(6,  90);
    m_table->setColumnWidth(7,  90);

    outer->addWidget(m_noDataLabel, 1);
    outer->addWidget(m_table, 1);
    m_table->hide();
}

void AnomalyTab::updateData(const QVector<AnomalyEntry> &entries)
{
    if (entries.isEmpty()) {
        m_table->hide();
        m_noDataLabel->show();
        m_countLabel->setText("");
        return;
    }

    m_noDataLabel->hide();
    m_table->show();
    m_table->setRowCount(entries.size());
    m_countLabel->setText(
        QString("  %1 anomal%2 detected")
            .arg(entries.size())
            .arg(entries.size() == 1 ? "y" : "ies"));

    for (int i = 0; i < entries.size(); ++i) {
        const AnomalyEntry &e = entries[i];

        auto makeItem = [](const QString &text,
                           const QColor &color = QColor("#cccccc"),
                           Qt::Alignment align = Qt::AlignLeft | Qt::AlignVCenter) {
            auto *item = new QTableWidgetItem(text);
            item->setForeground(QBrush(color));
            item->setTextAlignment(align);
            item->setFlags(Qt::ItemIsEnabled | Qt::ItemIsSelectable);
            return item;
        };

        // Anomaly type color
        QColor anomColor = QColor("#ef4444");
        if (e.anomaly == "PORT_SCAN") anomColor = QColor("#ef4444");
        else if (e.anomaly == "SYN_FLOOD") anomColor = QColor("#ef4444");
        else if (e.anomaly == "HIGH_BW")   anomColor = QColor("#ce9178");

        m_table->setItem(i, 0, makeItem(e.process, QColor("#cccccc")));
        m_table->setItem(i, 1, makeItem(e.exeShort(), QColor("#8a8a8a")));
        m_table->setItem(i, 2, makeItem(e.anomaly, anomColor));
        m_table->setItem(i, 3, makeItem(
            QString::number(e.newConnsLastSec), QColor("#cccccc"),
            Qt::AlignRight | Qt::AlignVCenter));
        m_table->setItem(i, 4, makeItem(
            QString::number(e.uniquePortsLastSec), QColor("#cccccc"),
            Qt::AlignRight | Qt::AlignVCenter));
        m_table->setItem(i, 5, makeItem(
            QString::number(e.totalConns), QColor("#cccccc"),
            Qt::AlignRight | Qt::AlignVCenter));
        m_table->setItem(i, 6, makeItem(
            e.formatRate(e.rateOutBps), QColor("#cccccc"),
            Qt::AlignRight | Qt::AlignVCenter));
        m_table->setItem(i, 7, makeItem(
            e.formatRate(e.rateInBps), QColor("#cccccc"),
            Qt::AlignRight | Qt::AlignVCenter));

        // Highlight entire row red background
        for (int col = 0; col < 8; ++col)
            if (m_table->item(i, col))
                m_table->item(i, col)->setBackground(QBrush(QColor("#2e1515")));
    }
}
