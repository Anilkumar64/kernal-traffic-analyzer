#include "AnomalyTab.h"
#include "Style.h"
#include "../core/AnomalyModel.h"
#include "delegates/ColorTextDelegate.h"
#include "delegates/MonoDelegate.h"

#include <QAction>
#include <QHeaderView>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QSortFilterProxyModel>
#include <QStackedWidget>
#include <QTableView>
#include <QVBoxLayout>

static QLabel *anomLabel(const QString &text, int px, int weight, const QColor &color, QWidget *parent)
{
    auto *l = new QLabel(text, parent);
    l->setFont(uiFont(px, weight));
    l->setStyleSheet(QString("color:%1;background:transparent;").arg(Style::css(color)));
    return l;
}

static QWidget *emptyAnomalies(QWidget *parent)
{
    auto *w = new QWidget(parent);
    auto *layout = new QVBoxLayout(w);
    layout->setAlignment(Qt::AlignCenter);
    layout->setSpacing(8);
    auto *icon = anomLabel(QString::fromUtf8("\342\234\223"), 40, QFont::Normal, KtaColors::Text3, w);
    icon->setAlignment(Qt::AlignCenter);
    auto *title = anomLabel("No anomalies detected", 15, QFont::DemiBold, KtaColors::Text1, w);
    title->setAlignment(Qt::AlignCenter);
    auto *sub = anomLabel("The kernel module will report unusual behavior here", 12, QFont::Normal, KtaColors::Text4, w);
    sub->setAlignment(Qt::AlignCenter);
    layout->addWidget(icon);
    layout->addWidget(title);
    layout->addWidget(sub);
    return w;
}

AnomalyTab::AnomalyTab(QWidget *parent) : QWidget(parent)
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
    titles->addWidget(anomLabel("Anomalies", 15, QFont::DemiBold, KtaColors::Text1, bar));
    titles->addWidget(anomLabel("Kernel-reported unusual network behavior", 11, QFont::Normal, KtaColors::Text3, bar));
    barLayout->addLayout(titles, 1);
    auto *filter = new QLineEdit(bar);
    filter->setFixedWidth(220);
    filter->setPlaceholderText("Search");
    filter->addAction(new QAction(QString::fromUtf8("\342\214\225"), filter), QLineEdit::LeadingPosition);
    auto *clear = new QPushButton("Clear", bar);
    clear->setFont(uiFont(12, QFont::DemiBold));
    clear->setStyleSheet(QString("QPushButton{background:%1;border:1px solid %2;color:%2;border-radius:6px;padding:6px 12px;}QPushButton:hover{background:%2;color:white;}")
        .arg(Style::css(KtaColors::RedD), Style::css(KtaColors::Red)));
    barLayout->addWidget(filter);
    barLayout->addWidget(clear);
    layout->addWidget(bar);

    m_model = new AnomalyModel(this);
    m_proxy = new QSortFilterProxyModel(this);
    m_proxy->setSourceModel(m_model);
    m_proxy->setFilterCaseSensitivity(Qt::CaseInsensitive);
    m_proxy->setFilterKeyColumn(-1);
    m_stack = new QStackedWidget(this);
    m_stack->addWidget(emptyAnomalies(m_stack));
    m_table = new QTableView(m_stack);
    m_table->setModel(m_proxy);
    m_table->setShowGrid(false);
    m_table->setAlternatingRowColors(true);
    m_table->verticalHeader()->hide();
    m_table->verticalHeader()->setDefaultSectionSize(36);
    m_table->horizontalHeader()->setSectionResizeMode(QHeaderView::Interactive);
    m_table->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_table->setSelectionMode(QAbstractItemView::SingleSelection);
    m_table->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_table->setFocusPolicy(Qt::NoFocus);
    m_table->setSortingEnabled(true);
    m_table->setItemDelegateForColumn(AnomalyModel::Pid, new MonoDelegate(KtaColors::Text3, m_table));
    m_table->setItemDelegateForColumn(AnomalyModel::Type, new ColorTextDelegate(KtaColors::Red, m_table));
    m_table->horizontalHeader()->resizeSection(AnomalyModel::Details, 420);
    m_stack->addWidget(m_table);
    layout->addWidget(m_stack, 1);
    connect(filter, &QLineEdit::textChanged, m_proxy, &QSortFilterProxyModel::setFilterFixedString);
    connect(clear, &QPushButton::clicked, m_model, &AnomalyModel::clear);
    connect(clear, &QPushButton::clicked, this, [this] { m_stack->setCurrentIndex(0); });
}

void AnomalyTab::updateData(const QVector<AnomalyEntry> &entries)
{
    m_model->updateData(entries);
    m_stack->setCurrentIndex(entries.isEmpty() ? 0 : 1);
}

int AnomalyTab::count() const { return m_model ? m_model->rowCount() : 0; }
