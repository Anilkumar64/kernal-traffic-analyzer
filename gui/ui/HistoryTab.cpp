#include "HistoryTab.h"
#include "Style.h"
#include "delegates/ColorTextDelegate.h"

#include <QAbstractTableModel>
#include <QComboBox>
#include <QHeaderView>
#include <QLabel>
#include <QPainter>
#include <QStackedWidget>
#include <QTabBar>
#include <QTableView>
#include <QVBoxLayout>

static QString histBytes(quint64 value)
{
    if (value < 1024) return QString("%1 B").arg(value);
    if (value < 1024 * 1024) return QString("%1 KB").arg(value / 1024.0, 0, 'f', 1);
    if (value < 1024ull * 1024 * 1024) return QString("%1 MB").arg(value / 1048576.0, 0, 'f', 1);
    return QString("%1 GB").arg(value / 1073741824.0, 0, 'f', 2);
}

class ProcessHistoryModel : public QAbstractTableModel
{
public:
    QVector<DailyTotal> today;
    QVector<DailyTotal> range;
    int days = 7;
    int rowCount(const QModelIndex & = {}) const override { return range.size(); }
    int columnCount(const QModelIndex & = {}) const override { return 5; }
    QVariant data(const QModelIndex &index, int role) const override
    {
        if (!index.isValid()) return {};
        const auto &r = range.at(index.row());
        auto it = std::find_if(today.begin(), today.end(), [&](const DailyTotal &d) { return d.process == r.process; });
        if (role == Qt::ForegroundRole) {
            if (index.column() == 1 || index.column() == 3) return KtaColors::Accent;
            if (index.column() == 2 || index.column() == 4) return KtaColors::Amber;
        }
        if (role == Qt::DisplayRole) {
            switch (index.column()) {
            case 0: return r.process;
            case 1: return it == today.end() ? "0 B" : histBytes(it->totalIn);
            case 2: return it == today.end() ? "0 B" : histBytes(it->totalOut);
            case 3: return histBytes(r.totalIn);
            case 4: return histBytes(r.totalOut);
            default: return {};
            }
        }
        return {};
    }
    QVariant headerData(int section, Qt::Orientation orientation, int role) const override
    {
        if (orientation != Qt::Horizontal || role != Qt::DisplayRole) return {};
        return QStringList({"PROCESS", "TODAY IN", "TODAY OUT", QString("%1-DAY IN").arg(days), QString("%1-DAY OUT").arg(days)}).value(section);
    }
    void setRows(QVector<DailyTotal> t, QVector<DailyTotal> r, int d)
    {
        beginResetModel();
        today = std::move(t);
        range = std::move(r);
        days = d;
        endResetModel();
    }
};

class BandwidthChart : public QWidget
{
public:
    explicit BandwidthChart(QWidget *parent = nullptr) : QWidget(parent) { setMinimumHeight(280); }
    void setRows(const QVector<DailyTotal> &rows)
    {
        m_labels.clear();
        m_inData.clear();
        m_outData.clear();
        for (const auto &row : rows) {
            m_labels.append(row.date.mid(5));
            m_inData.append(row.totalIn);
            m_outData.append(row.totalOut);
        }
        update();
    }
protected:
    void paintEvent(QPaintEvent *) override
    {
        QPainter p(this);
        p.setRenderHint(QPainter::Antialiasing);
        p.fillRect(rect(), KtaColors::BgBase);
        const int padL = 56, padR = 20, padT = 20, padB = 32;
        QRect plot(padL, padT, width() - padL - padR, height() - padT - padB);
        if (plot.width() <= 0 || plot.height() <= 0) return;
        quint64 maxVal = 1;
        for (int i = 0; i < m_inData.size(); ++i) maxVal = std::max({maxVal, m_inData[i], m_outData[i]});
        p.setFont(monoFont(10));
        for (int i = 0; i <= 4; ++i) {
            int y = plot.bottom() - (plot.height() * i / 4);
            p.setPen(QPen(KtaColors::Border, 1));
            p.drawLine(plot.left(), y, plot.right(), y);
            p.setPen(KtaColors::Text4);
            p.drawText(QRect(0, y - 8, padL - 6, 16), Qt::AlignRight | Qt::AlignVCenter, histBytes(maxVal * i / 4));
        }
        int n = m_inData.size();
        if (n == 0) return;
        double slotW = double(plot.width()) / n;
        double barW = slotW * 0.42;
        for (int i = 0; i < n; ++i) {
            double x = plot.left() + i * slotW;
            double inH = (double(m_inData[i]) / double(maxVal)) * plot.height();
            p.fillRect(QRectF(x + 2, plot.bottom() - inH, barW, inH), KtaColors::AccentD);
            p.fillRect(QRectF(x + 2, plot.bottom() - inH, barW, 2), KtaColors::Accent);
            double outH = (double(m_outData[i]) / double(maxVal)) * plot.height();
            p.fillRect(QRectF(x + barW + 4, plot.bottom() - outH, barW, outH), KtaColors::AmberD);
            p.fillRect(QRectF(x + barW + 4, plot.bottom() - outH, barW, 2), KtaColors::Amber);
            if (i % 5 == 0 || i == n - 1) {
                p.setPen(KtaColors::Text4);
                p.drawText(QRectF(x, plot.bottom() + 8, slotW, 16), Qt::AlignCenter, m_labels.value(i));
            }
        }
    }
private:
    QVector<QString> m_labels;
    QVector<quint64> m_inData;
    QVector<quint64> m_outData;
};

static QLabel *historyLabel(const QString &text, int px, int weight, const QColor &color, QWidget *parent)
{
    auto *l = new QLabel(text, parent);
    l->setFont(uiFont(px, weight));
    l->setStyleSheet(QString("color:%1;background:transparent;").arg(Style::css(color)));
    return l;
}

HistoryTab::HistoryTab(QWidget *parent) : QWidget(parent)
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
    titles->addWidget(historyLabel("History", 15, QFont::DemiBold, KtaColors::Text1, bar));
    titles->addWidget(historyLabel("Bandwidth totals by process and day", 11, QFont::Normal, KtaColors::Text3, bar));
    barLayout->addLayout(titles, 1);
    m_days = new QComboBox(bar);
    m_days->addItems({"7", "30", "90"});
    m_days->setCurrentText("30");
    m_days->setFont(monoFont(12));
    m_days->setStyleSheet(QString("QComboBox{background:%1;border:1px solid %2;border-radius:6px;color:%3;padding:6px 24px 6px 10px;}QComboBox::drop-down{border:none;}")
        .arg(Style::css(KtaColors::BgRaised), Style::css(KtaColors::BorderMd), Style::css(KtaColors::Text2)));
    barLayout->addWidget(m_days);
    layout->addWidget(bar);

    auto *tabs = new QTabBar(this);
    tabs->addTab("By Process");
    tabs->addTab("By Day");
    tabs->setDrawBase(false);
    tabs->setStyleSheet(QString("QTabBar{background:%1;border-bottom:1px solid %2;}QTabBar::tab{background:%1;color:%3;padding:11px 18px;border:none;}QTabBar::tab:selected{color:%4;border-bottom:2px solid %5;}")
        .arg(Style::css(KtaColors::BgSurface), Style::css(KtaColors::Border), Style::css(KtaColors::Text3), Style::css(KtaColors::Text1), Style::css(KtaColors::Accent)));
    layout->addWidget(tabs);

    auto *stack = new QStackedWidget(this);
    auto *model = new ProcessHistoryModel;
    model->setParent(this);
    m_processModel = model;
    auto *table = new QTableView(stack);
    table->setModel(model);
    table->setAlternatingRowColors(true);
    table->setShowGrid(false);
    table->verticalHeader()->hide();
    table->verticalHeader()->setDefaultSectionSize(36);
    table->horizontalHeader()->setSectionResizeMode(QHeaderView::Interactive);
    table->setItemDelegateForColumn(1, new ColorTextDelegate(KtaColors::Accent, table));
    table->setItemDelegateForColumn(2, new ColorTextDelegate(KtaColors::Amber, table));
    table->setItemDelegateForColumn(3, new ColorTextDelegate(KtaColors::Accent, table));
    table->setItemDelegateForColumn(4, new ColorTextDelegate(KtaColors::Amber, table));
    m_chart = new BandwidthChart(stack);
    stack->addWidget(table);
    stack->addWidget(m_chart);
    layout->addWidget(stack, 1);
    connect(tabs, &QTabBar::currentChanged, stack, &QStackedWidget::setCurrentIndex);
    connect(m_days, &QComboBox::currentTextChanged, this, &HistoryTab::refresh);
}

void HistoryTab::refresh()
{
    const int days = m_days->currentText().toInt();
    auto &db = HistoryDB::instance();
    auto *model = static_cast<ProcessHistoryModel *>(m_processModel);
    model->setRows(db.getAllDailyTotals(1), db.getAllDailyTotals(days), days);
    m_chart->setRows(db.getAllDailyTotals(qMin(30, days)));
}
