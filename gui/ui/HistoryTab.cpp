#include "HistoryTab.h"
#include <QAbstractTableModel>
#include <QHeaderView>
#include <QPainter>
#include <QSpinBox>
#include <QTabBar>
#include <QStackedWidget>
#include <QTableView>
#include <QVBoxLayout>

static QString bytes(quint64 value)
{
    if (value < 1024) return QString("%1 B").arg(value);
    if (value < 1024 * 1024) return QString("%1 KB").arg(value / 1024.0, 0, 'f', 1);
    if (value < 1024ull * 1024 * 1024) return QString("%1 MB").arg(value / 1048576.0, 0, 'f', 1);
    return QString("%1 GB").arg(value / 1073741824.0, 0, 'f', 2);
}

class ProcessHistoryModel : public QAbstractTableModel {
public:
    QVector<DailyTotal> today;
    QVector<DailyTotal> range;
    int rowCount(const QModelIndex & = {}) const override { return range.size(); }
    int columnCount(const QModelIndex & = {}) const override { return 5; }
    QVariant data(const QModelIndex &index, int role) const override {
        if (!index.isValid() || role != Qt::DisplayRole) return {};
        const auto &r = range.at(index.row());
        auto it = std::find_if(today.begin(), today.end(), [&](const DailyTotal &d) { return d.process == r.process; });
        switch (index.column()) {
        case 0: return r.process;
        case 1: return it == today.end() ? "0 B" : bytes(it->totalIn);
        case 2: return it == today.end() ? "0 B" : bytes(it->totalOut);
        case 3: return bytes(r.totalIn);
        case 4: return bytes(r.totalOut);
        default: return {};
        }
    }
    QVariant headerData(int section, Qt::Orientation orientation, int role) const override {
        if (orientation != Qt::Horizontal || role != Qt::DisplayRole) return {};
        static const QStringList headers = {"PROCESS", "TODAY IN", "TODAY OUT", "7-DAY IN", "7-DAY OUT"};
        return headers.value(section);
    }
    void setRows(QVector<DailyTotal> t, QVector<DailyTotal> r) { beginResetModel(); today = std::move(t); range = std::move(r); endResetModel(); }
};

class DayChart : public QWidget {
public:
    QVector<DailyTotal> rows;
    void setRows(QVector<DailyTotal> value) { rows = std::move(value); update(); }
protected:
    void paintEvent(QPaintEvent *) override {
        QPainter p(this);
        p.fillRect(rect(), QColor("#1c1c1c"));
        if (rows.isEmpty()) return;
        const auto area = rect().adjusted(40, 20, -12, -30);
        quint64 max = 1;
        for (const auto &row : rows) max = qMax(max, row.totalIn + row.totalOut);
        const int gap = 4;
        const int barW = qMax(3, (area.width() - gap * (rows.size() - 1)) / rows.size());
        p.setPen(QColor("#707070"));
        p.drawText(4, area.top() + 12, bytes(max));
        p.drawText(4, area.bottom(), "0");
        p.setPen(Qt::NoPen);
        p.setBrush(QColor("#4a9eff"));
        for (int i = 0; i < rows.size(); ++i) {
            const int h = int(double(rows[i].totalIn + rows[i].totalOut) / double(max) * area.height());
            p.drawRect(area.left() + i * (barW + gap), area.bottom() - h, barW, h);
        }
    }
};

HistoryTab::HistoryTab(QWidget *parent) : QWidget(parent)
{
    auto *layout = new QVBoxLayout(this);
    auto *top = new QWidget(this);
    auto *topLayout = new QHBoxLayout(top);
    auto *tabs = new QTabBar(top);
    tabs->addTab("By Process");
    tabs->addTab("By Day");
    m_days = new QSpinBox(top);
    m_days->setRange(7, 90);
    m_days->setSingleStep(23);
    m_days->setValue(30);
    topLayout->addWidget(tabs);
    topLayout->addStretch();
    topLayout->addWidget(m_days);
    layout->addWidget(top);
    auto *stack = new QStackedWidget(this);
    auto *table = new QTableView(stack);
    auto *model = new ProcessHistoryModel;
    model->setParent(this);
    m_processModel = model;
    table->setModel(model);
    table->setAlternatingRowColors(true);
    table->setShowGrid(false);
    table->verticalHeader()->hide();
    table->horizontalHeader()->setSectionResizeMode(QHeaderView::Interactive);
    auto *chart = new DayChart;
    chart->setObjectName("dayChart");
    stack->addWidget(table);
    stack->addWidget(chart);
    layout->addWidget(stack, 1);
    connect(tabs, &QTabBar::currentChanged, stack, &QStackedWidget::setCurrentIndex);
    connect(m_days, &QSpinBox::valueChanged, this, &HistoryTab::refresh);
}

void HistoryTab::refresh()
{
    auto &db = HistoryDB::instance();
    auto *model = static_cast<ProcessHistoryModel *>(m_processModel);
    model->setRows(db.getAllDailyTotals(1), db.getAllDailyTotals(m_days->value()));
    auto *chart = findChild<DayChart *>("dayChart");
    if (chart) chart->setRows(db.getAllDailyTotals(qMin(30, m_days->value())));
}
