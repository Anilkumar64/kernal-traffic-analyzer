#include "NetworkPerfTab.h"
#include "Style.h"
#include "delegates/MonoDelegate.h"

#include <QAction>
#include <QAbstractTableModel>
#include <QDateTime>
#include <QFile>
#include <QGridLayout>
#include <QHeaderView>
#include <QLabel>
#include <QLineEdit>
#include <QPainter>
#include <QProgressBar>
#include <QSortFilterProxyModel>
#include <QTableView>
#include <QTextStream>
#include <QVBoxLayout>

struct PerfRow {
    QString iface;
    double rtt = 0.0;
    double jitter = 0.0;
    double loss = 0.0;
    QString updated;
};

static QColor metricColor(double v)
{
    if (v < 50.0) return KtaColors::Teal;
    if (v < 150.0) return KtaColors::Amber;
    return KtaColors::Red;
}

class PerfModel : public QAbstractTableModel
{
public:
    QVector<PerfRow> rows;
    int rowCount(const QModelIndex & = {}) const override { return rows.size(); }
    int columnCount(const QModelIndex & = {}) const override { return 5; }
    QVariant data(const QModelIndex &index, int role) const override
    {
        if (!index.isValid() || index.row() >= rows.size()) return {};
        const auto &r = rows.at(index.row());
        if (role == Qt::ForegroundRole && index.column() >= 1 && index.column() <= 3)
            return metricColor(index.column() == 3 ? r.loss * 50.0 : (index.column() == 2 ? r.jitter : r.rtt));
        if (role == Qt::DisplayRole) {
            switch (index.column()) {
            case 0: return r.iface;
            case 1: return QString::number(r.rtt, 'f', 1);
            case 2: return QString::number(r.jitter, 'f', 1);
            case 3: return QString::number(r.loss, 'f', 1);
            case 4: return r.updated;
            default: return {};
            }
        }
        return {};
    }
    QVariant headerData(int section, Qt::Orientation orientation, int role) const override
    {
        if (orientation != Qt::Horizontal || role != Qt::DisplayRole) return {};
        static const QStringList headers = {"INTERFACE", "RTT (MS)", "JITTER (MS)", "PACKET LOSS %", "LAST UPDATED"};
        return headers.value(section);
    }
    void setRows(QVector<PerfRow> value) { beginResetModel(); rows = std::move(value); endResetModel(); }
};

class MetricBar : public QWidget
{
public:
    explicit MetricBar(QWidget *parent = nullptr) : QWidget(parent) { setFixedHeight(4); }
    void setValue(double v, double max, QColor color) { m_value = v; m_max = max; m_color = color; update(); }
protected:
    void paintEvent(QPaintEvent *) override
    {
        QPainter p(this);
        p.setRenderHint(QPainter::Antialiasing);
        QRectF r = rect();
        p.setPen(Qt::NoPen);
        p.setBrush(KtaColors::BgRaised);
        p.drawRoundedRect(r, 2, 2);
        r.setWidth(r.width() * qBound(0.0, m_value / m_max, 1.0));
        p.setBrush(m_color);
        p.drawRoundedRect(r, 2, 2);
    }
private:
    double m_value = 0.0;
    double m_max = 1.0;
    QColor m_color = KtaColors::Teal;
};

class PerfCard : public QWidget
{
public:
    explicit PerfCard(const PerfRow &row, QWidget *parent = nullptr) : QWidget(parent)
    {
        setMinimumHeight(230);
        auto *layout = new QVBoxLayout(this);
        layout->setContentsMargins(20, 18, 20, 18);
        layout->setSpacing(10);
        auto *head = new QHBoxLayout;
        auto *label = new QLabel("INTERFACE", this);
        label->setFont(uiFont(10, QFont::DemiBold));
        label->setStyleSheet(QString("color:%1;background:transparent;").arg(Style::css(KtaColors::Text4)));
        auto *iface = new QLabel(row.iface, this);
        iface->setFont(monoFont(12));
        iface->setStyleSheet(QString("color:%1;background:transparent;").arg(Style::css(KtaColors::Accent)));
        head->addWidget(label);
        head->addStretch();
        head->addWidget(iface);
        layout->addLayout(head);
        auto *rule = new QWidget(this);
        rule->setFixedHeight(1);
        rule->setStyleSheet(QString("background:%1;").arg(Style::css(KtaColors::Border)));
        layout->addWidget(rule);
        addMetric(layout, "ROUND TRIP TIME", QString("%1 ms").arg(row.rtt, 0, 'f', 1), row.rtt, 200.0, metricColor(row.rtt), "Latency");
        addMetric(layout, "JITTER", QString("%1 ms").arg(row.jitter, 0, 'f', 1), row.jitter, 50.0, metricColor(row.jitter), "Variation");
        addMetric(layout, "PACKET LOSS", QString("%1%").arg(row.loss, 0, 'f', 1), row.loss, 10.0, metricColor(row.loss * 50.0), QString());
    }
protected:
    void paintEvent(QPaintEvent *) override
    {
        QPainter p(this);
        p.setRenderHint(QPainter::Antialiasing);
        p.setBrush(KtaColors::BgCard);
        p.setPen(QPen(KtaColors::Border, 1));
        p.drawRoundedRect(rect().adjusted(0, 0, -1, -1), 10, 10);
    }
private:
    void addMetric(QVBoxLayout *layout, const QString &name, const QString &value, double raw, double max, QColor color, const QString &barLabel)
    {
        auto *n = new QLabel(name, this);
        n->setFont(uiFont(10, QFont::DemiBold));
        n->setStyleSheet(QString("color:%1;background:transparent;").arg(Style::css(KtaColors::Text4)));
        auto *v = new QLabel(value, this);
        v->setFont(monoFont(22));
        v->setStyleSheet(QString("color:%1;background:transparent;font-weight:600;").arg(Style::css(color)));
        layout->addWidget(n);
        layout->addWidget(v);
        if (!barLabel.isEmpty()) {
            auto *bar = new MetricBar(this);
            bar->setValue(raw, max, color);
            layout->addWidget(bar);
        }
    }
};

NetworkPerfTab::NetworkPerfTab(QWidget *parent) : QWidget(parent)
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
    auto *title = new QLabel("Network Perf", bar);
    title->setFont(uiFont(15, QFont::DemiBold));
    title->setStyleSheet(QString("color:%1;background:transparent;").arg(Style::css(KtaColors::Text1)));
    auto *sub = new QLabel("Interface latency, jitter, and packet-loss summary", bar);
    sub->setFont(uiFont(11));
    sub->setStyleSheet(QString("color:%1;background:transparent;").arg(Style::css(KtaColors::Text3)));
    titles->addWidget(title);
    titles->addWidget(sub);
    barLayout->addLayout(titles, 1);
    auto *filter = new QLineEdit(bar);
    filter->setFixedWidth(220);
    filter->setPlaceholderText("Search");
    filter->addAction(new QAction(QString::fromUtf8("\342\214\225"), filter), QLineEdit::LeadingPosition);
    barLayout->addWidget(filter);
    layout->addWidget(bar);
    auto *content = new QWidget(this);
    auto *contentLayout = new QVBoxLayout(content);
    contentLayout->setContentsMargins(24, 16, 24, 16);
    contentLayout->setSpacing(16);
    auto *cardHost = new QWidget(content);
    m_cards = new QGridLayout(cardHost);
    m_cards->setContentsMargins(0, 0, 0, 0);
    m_cards->setHorizontalSpacing(12);
    m_cards->setVerticalSpacing(12);
    contentLayout->addWidget(cardHost);
    auto *table = new QTableView(content);
    auto *model = new PerfModel;
    model->setParent(this);
    m_model = model;
    m_proxy = new QSortFilterProxyModel(this);
    m_proxy->setSourceModel(model);
    m_proxy->setFilterCaseSensitivity(Qt::CaseInsensitive);
    m_proxy->setFilterKeyColumn(-1);
    table->setModel(m_proxy);
    table->setAlternatingRowColors(true);
    table->setShowGrid(false);
    table->verticalHeader()->setDefaultSectionSize(36);
    table->verticalHeader()->hide();
    table->horizontalHeader()->setSectionResizeMode(QHeaderView::Interactive);
    table->setItemDelegateForColumn(0, new MonoDelegate(KtaColors::Accent, table));
    contentLayout->addWidget(table, 1);
    layout->addWidget(content, 1);
    connect(filter, &QLineEdit::textChanged, m_proxy, &QSortFilterProxyModel::setFilterFixedString);
}

void NetworkPerfTab::updateData(const ProcSnapshot &snap)
{
    Q_UNUSED(snap);
    QVector<PerfRow> rows;
    QFile dev("/proc/net/dev");
    if (dev.open(QIODevice::ReadOnly | QIODevice::Text)) {
        QTextStream in(&dev);
        int lineNo = 0;
        while (!in.atEnd()) {
            const QString line = in.readLine().trimmed();
            if (++lineNo <= 2 || !line.contains(':')) continue;
            const QString iface = line.section(':', 0, 0).trimmed();
            rows.append({iface, 0.0, 0.0, 0.0, QTime::currentTime().toString("hh:mm:ss")});
            if (rows.size() == 3) break;
        }
    }
    if (rows.isEmpty()) rows.append({"lo", 0.0, 0.0, 0.0, QTime::currentTime().toString("hh:mm:ss")});
    while (auto *item = m_cards->takeAt(0)) {
        delete item->widget();
        delete item;
    }
    for (int i = 0; i < rows.size(); ++i) m_cards->addWidget(new PerfCard(rows[i]), i / 3, i % 3);
    static_cast<PerfModel *>(m_model)->setRows(rows);
}
