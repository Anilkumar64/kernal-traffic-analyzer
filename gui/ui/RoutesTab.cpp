#include "RoutesTab.h"
#include "Style.h"
#include "../core/RouteModel.h"
#include "delegates/ColorTextDelegate.h"
#include "delegates/MonoDelegate.h"

#include <QAction>
#include <QHeaderView>
#include <QLabel>
#include <QLineEdit>
#include <QSortFilterProxyModel>
#include <QSplitter>
#include <QStackedWidget>
#include <QTableView>
#include <QVBoxLayout>

class RttDelegate : public QStyledItemDelegate
{
public:
    explicit RttDelegate(QObject *parent = nullptr) : QStyledItemDelegate(parent) {}
    void initStyleOption(QStyleOptionViewItem *option, const QModelIndex &index) const override
    {
        QStyledItemDelegate::initStyleOption(option, index);
        option->state &= ~QStyle::State_HasFocus;
        option->font = monoFont(12);
        const double v = index.data().toDouble();
        option->palette.setColor(QPalette::Text, v < 50 ? KtaColors::Teal : (v < 150 ? KtaColors::Amber : KtaColors::Red));
    }
    QSize sizeHint(const QStyleOptionViewItem &, const QModelIndex &) const override { return {-1, 36}; }
};

static QLabel *routeLabel(const QString &text, int px, int weight, const QColor &color, QWidget *parent)
{
    auto *l = new QLabel(text, parent);
    l->setFont(uiFont(px, weight));
    l->setStyleSheet(QString("color:%1;background:transparent;").arg(Style::css(color)));
    return l;
}

static void setupRouteTable(QTableView *table)
{
    table->setShowGrid(false);
    table->setAlternatingRowColors(true);
    table->verticalHeader()->setDefaultSectionSize(36);
    table->verticalHeader()->hide();
    table->horizontalHeader()->setSectionResizeMode(QHeaderView::Interactive);
    table->setSortingEnabled(true);
    table->setSelectionBehavior(QAbstractItemView::SelectRows);
    table->setSelectionMode(QAbstractItemView::SingleSelection);
    table->setEditTriggers(QAbstractItemView::NoEditTriggers);
    table->setFocusPolicy(Qt::NoFocus);
}

RoutesTab::RoutesTab(QWidget *parent) : QWidget(parent)
{
    auto *layout = new QVBoxLayout(this);
    layout->setContentsMargins(0, 0, 0, 0);
    layout->setSpacing(0);
    auto *bar = new QWidget(this);
    bar->setFixedHeight(62);
    bar->setStyleSheet(QString("background:%1;border-bottom:1px solid %2;").arg(Style::css(KtaColors::BgSurface), Style::css(KtaColors::Border)));
    auto *barLayout = new QHBoxLayout(bar);
    barLayout->setContentsMargins(16, 16, 16, 0);
    auto *titles = new QVBoxLayout;
    titles->setSpacing(2);
    titles->addWidget(routeLabel("Routes", 15, QFont::DemiBold, KtaColors::Text1, bar));
    titles->addWidget(routeLabel("Destination traces and hop timing", 11, QFont::Normal, KtaColors::Text3, bar));
    barLayout->addLayout(titles, 1);
    auto *filter = new QLineEdit(bar);
    filter->setFixedWidth(220);
    filter->setPlaceholderText("Search");
    filter->addAction(new QAction(QString::fromUtf8("\342\214\225"), filter), QLineEdit::LeadingPosition);
    barLayout->addWidget(filter);
    layout->addWidget(bar);

    auto *splitter = new QSplitter(Qt::Vertical, this);
    m_model = new RouteModel(this);
    m_hopModel = new RouteHopModel(this);
    m_proxy = new QSortFilterProxyModel(this);
    m_proxy->setSourceModel(m_model);
    m_proxy->setFilterCaseSensitivity(Qt::CaseInsensitive);
    m_proxy->setFilterKeyColumn(-1);
    m_table = new QTableView(splitter);
    m_table->setModel(m_proxy);
    setupRouteTable(m_table);
    m_table->setItemDelegateForColumn(RouteModel::Destination, new MonoDelegate(KtaColors::Text2, m_table));
    m_table->setItemDelegateForColumn(RouteModel::Domain, new ColorTextDelegate(KtaColors::Purple, m_table));
    m_table->horizontalHeader()->resizeSection(RouteModel::Domain, 260);
    splitter->addWidget(m_table);

    auto *bottom = new QWidget(splitter);
    bottom->setMinimumHeight(200);
    auto *bottomLayout = new QVBoxLayout(bottom);
    bottomLayout->setContentsMargins(0, 0, 0, 0);
    bottomLayout->setSpacing(0);
    m_hopTitle = routeLabel(QString::fromUtf8("\342\206\222  Hop details - select a destination above"), 13, QFont::DemiBold, KtaColors::Text2, bottom);
    m_hopTitle->setFixedHeight(42);
    m_hopTitle->setContentsMargins(16, 0, 0, 0);
    m_hopStack = new QStackedWidget(bottom);
    auto *hint = routeLabel("Select a destination above", 12, QFont::Normal, KtaColors::Text4, m_hopStack);
    hint->setAlignment(Qt::AlignCenter);
    hint->setFont(uiFont(12, QFont::StyleItalic));
    auto *hopTable = new QTableView(m_hopStack);
    hopTable->setModel(m_hopModel);
    setupRouteTable(hopTable);
    hopTable->setItemDelegateForColumn(RouteHopModel::Ip, new MonoDelegate(KtaColors::Text2, hopTable));
    hopTable->setItemDelegateForColumn(RouteHopModel::Rtt, new RttDelegate(hopTable));
    m_hopStack->addWidget(hint);
    m_hopStack->addWidget(hopTable);
    bottomLayout->addWidget(m_hopTitle);
    bottomLayout->addWidget(m_hopStack, 1);
    splitter->addWidget(bottom);
    splitter->setSizes({420, 200});
    layout->addWidget(splitter, 1);
    connect(filter, &QLineEdit::textChanged, m_proxy, &QSortFilterProxyModel::setFilterFixedString);
    connect(m_table, &QTableView::clicked, this, &RoutesTab::selectRoute);
}

void RoutesTab::updateData(const QVector<RouteEntry> &entries)
{
    m_model->updateData(entries);
}

void RoutesTab::selectRoute(const QModelIndex &index)
{
    const auto source = m_proxy->mapToSource(index);
    if (!source.isValid()) return;
    const auto &entry = m_model->entryAt(source.row());
    m_hopTitle->setText(QString::fromUtf8("\342\206\222  Hop details - %1").arg(entry.destIp));
    m_hopModel->updateData(entry.hops);
    m_hopStack->setCurrentIndex(1);
}
