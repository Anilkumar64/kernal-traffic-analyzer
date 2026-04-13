#include "DnsTab.h"
#include "Style.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QFrame>
#include <QDateTime>

DnsTab::DnsTab(QWidget *parent) : QWidget(parent)
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
    auto *title = new QLabel("DNS Map", topBar);
    title->setStyleSheet(
        "color:#cccccc;font-size:16px;font-weight:600;font-family:'Ubuntu Mono';");
    m_countLabel = new QLabel("", topBar);
    m_countLabel->setStyleSheet("color:#8a8a8a;font-size:11px;");
    tl->addWidget(title);
    tl->addWidget(m_countLabel);
    tl->addStretch();
    outer->addWidget(topBar);

    auto *div = new QFrame(this);
    div->setFrameShape(QFrame::HLine);
    div->setStyleSheet("background:#3e3e42;max-height:1px;");
    outer->addWidget(div);

    // Table
    m_table = new QTableWidget(0, 7, this);
    m_table->setHorizontalHeaderLabels({
        "DOMAIN", "IP", "TTL", "QUERIED BY", "PID", "FIRST SEEN", "LAST SEEN"
    });
    m_table->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_table->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_table->setAlternatingRowColors(true);
    m_table->setShowGrid(false);
    m_table->verticalHeader()->setVisible(false);
    m_table->verticalHeader()->setDefaultSectionSize(48);
    m_table->horizontalHeader()->setSectionResizeMode(QHeaderView::Interactive);
    m_table->horizontalHeader()->setStretchLastSection(false);
    m_table->setColumnWidth(0, 220);
    m_table->setColumnWidth(1, 140);
    m_table->setColumnWidth(2,  80);
    m_table->setColumnWidth(3, 140);
    m_table->setColumnWidth(4,  60);
    m_table->setColumnWidth(5, 160);
    m_table->setColumnWidth(6, 160);

    outer->addWidget(m_table, 1);
}

void DnsTab::updateData(const QVector<DnsEntry> &entries)
{
    m_table->setRowCount(entries.size());
    m_countLabel->setText(QString("  %1 entries").arg(entries.size()));

    for (int i = 0; i < entries.size(); ++i) {
        const DnsEntry &e = entries[i];

        auto makeItem = [](const QString &text, const QColor &color = QColor("#cccccc")) {
            auto *item = new QTableWidgetItem(text);
            item->setForeground(QBrush(color));
            item->setFlags(Qt::ItemIsEnabled | Qt::ItemIsSelectable);
            return item;
        };

        QString firstSeen = QDateTime::fromSecsSinceEpoch(e.firstSeen)
                                .toString("hh:mm:ss");
        QString lastSeen  = QDateTime::fromSecsSinceEpoch(e.lastSeen)
                                .toString("hh:mm:ss");

        // Color TTL based on remaining time
        QColor ttlColor = e.ttlRemaining > 60 ? QColor("#10b981") :
                          e.ttlRemaining > 10 ? QColor("#ce9178") :
                                                QColor("#ef4444");

        m_table->setItem(i, 0, makeItem(e.domain,        QColor("#6366f1")));
        m_table->setItem(i, 1, makeItem(e.ip,            QColor("#cccccc")));
        m_table->setItem(i, 2, makeItem(e.ttlString(),   ttlColor));
        m_table->setItem(i, 3, makeItem(e.queriedByComm, QColor("#8a8a8a")));
        m_table->setItem(i, 4, makeItem(QString::number(e.queriedByPid),
                                         QColor("#8a8a8a")));
        m_table->setItem(i, 5, makeItem(firstSeen,       QColor("#8a8a8a")));
        m_table->setItem(i, 6, makeItem(lastSeen,        QColor("#8a8a8a")));
    }
}
