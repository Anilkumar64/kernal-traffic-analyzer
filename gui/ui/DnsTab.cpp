#include "DnsTab.h"
#include "Style.h"
#include "../core/DnsModel.h"
#include "delegates/ColorTextDelegate.h"
#include "delegates/MonoDelegate.h"
#include "delegates/TtlBarDelegate.h"

#include <QAction>
#include <QHeaderView>
#include <QLabel>
#include <QLineEdit>
#include <QSortFilterProxyModel>
#include <QTableView>
#include <QVBoxLayout>

static QLabel *dnsLabel(const QString &text, int px, int weight, const QColor &color, QWidget *parent)
{
    auto *l = new QLabel(text, parent);
    l->setFont(uiFont(px, weight));
    l->setStyleSheet(QString("color:%1;background:transparent;").arg(Style::css(color)));
    return l;
}

static QWidget *dnsTopBar(QLineEdit **filter, QWidget *parent)
{
    auto *bar = new QWidget(parent);
    bar->setFixedHeight(62);
    bar->setStyleSheet(QString("background:%1;border-bottom:1px solid %2;").arg(Style::css(KtaColors::BgSurface), Style::css(KtaColors::Border)));
    auto *layout = new QHBoxLayout(bar);
    layout->setContentsMargins(16, 16, 16, 0);
    auto *titles = new QVBoxLayout;
    titles->setSpacing(2);
    titles->addWidget(dnsLabel("DNS", 15, QFont::DemiBold, KtaColors::Text1, bar));
    titles->addWidget(dnsLabel("Resolved domains observed by the kernel module", 11, QFont::Normal, KtaColors::Text3, bar));
    layout->addLayout(titles, 1);
    *filter = new QLineEdit(bar);
    (*filter)->setFixedWidth(220);
    (*filter)->setPlaceholderText("Search");
    (*filter)->addAction(new QAction(QString::fromUtf8("\342\214\225"), *filter), QLineEdit::LeadingPosition);
    layout->addWidget(*filter);
    return bar;
}

static void setupDnsTable(QTableView *view)
{
    view->setShowGrid(false);
    view->setAlternatingRowColors(true);
    view->verticalHeader()->hide();
    view->verticalHeader()->setDefaultSectionSize(36);
    view->horizontalHeader()->setStretchLastSection(false);
    view->setSelectionBehavior(QAbstractItemView::SelectRows);
    view->setSelectionMode(QAbstractItemView::SingleSelection);
    view->setEditTriggers(QAbstractItemView::NoEditTriggers);
    view->setFocusPolicy(Qt::NoFocus);
    view->setSortingEnabled(true);
    view->horizontalHeader()->setSectionResizeMode(QHeaderView::Interactive);
}

DnsTab::DnsTab(QWidget *parent) : QWidget(parent)
{
    auto *layout = new QVBoxLayout(this);
    layout->setContentsMargins(0, 0, 0, 0);
    layout->setSpacing(0);
    QLineEdit *filter = nullptr;
    layout->addWidget(dnsTopBar(&filter, this));
    m_model = new DnsModel(this);
    m_proxy = new QSortFilterProxyModel(this);
    m_proxy->setSourceModel(m_model);
    m_proxy->setFilterCaseSensitivity(Qt::CaseInsensitive);
    m_proxy->setFilterKeyColumn(-1);
    m_table = new QTableView(this);
    setupDnsTable(m_table);
    m_table->setModel(m_proxy);
    m_table->setItemDelegateForColumn(DnsModel::Ip, new MonoDelegate(KtaColors::Text2, m_table));
    m_table->setItemDelegateForColumn(DnsModel::Domain, new ColorTextDelegate(KtaColors::Purple, m_table));
    m_table->setItemDelegateForColumn(DnsModel::Ttl, new TtlBarDelegate(m_table));
    m_table->horizontalHeader()->resizeSection(DnsModel::Domain, 260);
    m_table->horizontalHeader()->resizeSection(DnsModel::Ttl, 170);
    layout->addWidget(m_table, 1);
    connect(filter, &QLineEdit::textChanged, m_proxy, &QSortFilterProxyModel::setFilterFixedString);
}

void DnsTab::updateData(const QVector<DnsEntry> &entries) { m_model->updateData(entries); }
