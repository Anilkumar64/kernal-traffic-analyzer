#include "ConnectionsTab.h"
#include "StatCard.h"
#include "Style.h"
#include "../core/TrafficModel.h"
#include "delegates/ColorTextDelegate.h"
#include "delegates/MonoDelegate.h"
#include "delegates/ProtoBadgeDelegate.h"
#include "delegates/RateBarDelegate.h"
#include "delegates/StateBadgeDelegate.h"

#include <QAction>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QLabel>
#include <QLineEdit>
#include <QPainter>
#include <QPropertyAnimation>
#include <QSet>
#include <QSortFilterProxyModel>
#include <QTableView>
#include <QVBoxLayout>
#include <numeric>

class ToggleSwitch : public QWidget
{
    Q_OBJECT
    Q_PROPERTY(qreal thumb READ thumb WRITE setThumb)
public:
    explicit ToggleSwitch(QWidget *parent = nullptr) : QWidget(parent)
    {
        setFixedSize(30, 16);
        setCursor(Qt::PointingHandCursor);
        m_anim = new QPropertyAnimation(this, "thumb", this);
        m_anim->setDuration(140);
    }
    bool isChecked() const { return m_checked; }
    qreal thumb() const { return m_thumb; }
    void setThumb(qreal v) { m_thumb = v; update(); }
signals:
    void toggled(bool checked);
protected:
    void mousePressEvent(QMouseEvent *) override
    {
        m_checked = !m_checked;
        m_anim->stop();
        m_anim->setStartValue(m_thumb);
        m_anim->setEndValue(m_checked ? 1.0 : 0.0);
        m_anim->start();
        emit toggled(m_checked);
    }
    void paintEvent(QPaintEvent *) override
    {
        QPainter p(this);
        p.setRenderHint(QPainter::Antialiasing);
        QRectF track = rect().adjusted(0.5, 0.5, -0.5, -0.5);
        p.setBrush(m_checked ? KtaColors::Accent : KtaColors::BgRaised);
        p.setPen(QPen(m_checked ? KtaColors::Accent : KtaColors::BorderMd, 1));
        p.drawRoundedRect(track, 8, 8);
        const qreal x = 3 + m_thumb * 14;
        p.setPen(Qt::NoPen);
        p.setBrush(Qt::white);
        p.drawEllipse(QRectF(x, 3, 10, 10));
    }
private:
    bool m_checked = false;
    qreal m_thumb = 0.0;
    QPropertyAnimation *m_anim = nullptr;
};

class ConnectionProxy : public QSortFilterProxyModel
{
public:
    bool showInactive = false;
protected:
    bool filterAcceptsRow(int row, const QModelIndex &parent) const override
    {
        if (!QSortFilterProxyModel::filterAcceptsRow(row, parent)) return false;
        if (showInactive) return true;
        const QString state = sourceModel()->index(row, TrafficModel::State, parent).data().toString();
        return state != "CLOSED" && state != "FIN_WAIT" && state != "FIN_WAIT2" && state != "TIME_WAIT";
    }
};

static QString formatBytes(qint64 b)
{
    if (b < 1024) return QString("%1 B").arg(b);
    if (b < 1048576) return QString("%1 KB").arg(b / 1024.0, 0, 'f', 1);
    if (b < 1073741824) return QString("%1 MB").arg(b / 1048576.0, 0, 'f', 1);
    return QString("%1 GB").arg(b / 1073741824.0, 0, 'f', 2);
}

static QString formatRate(quint64 bps)
{
    if (bps == 0) return "-";
    if (bps < 1024) return QString("%1 B/s").arg(bps);
    if (bps < 1048576) return QString("%1 KB/s").arg(bps / 1024.0, 0, 'f', 1);
    return QString("%1 MB/s").arg(bps / 1048576.0, 0, 'f', 1);
}

static QLabel *label(const QString &text, int px, int weight, const QColor &color, QWidget *parent)
{
    auto *l = new QLabel(text, parent);
    l->setFont(uiFont(px, weight));
    l->setStyleSheet(QString("color:%1;background:transparent;").arg(Style::css(color)));
    return l;
}

static QLineEdit *searchField(const QString &placeholder, QWidget *parent)
{
    auto *field = new QLineEdit(parent);
    field->setFixedWidth(220);
    field->setPlaceholderText(placeholder);
    auto *action = new QAction(QString::fromUtf8("\342\214\225"), field);
    field->addAction(action, QLineEdit::LeadingPosition);
    return field;
}

static QWidget *topBar(const QString &title, const QString &subtitle, QLineEdit **search, QWidget *extra, QWidget *parent)
{
    auto *bar = new QWidget(parent);
    bar->setFixedHeight(62);
    bar->setStyleSheet(QString("background:%1;border-bottom:1px solid %2;").arg(Style::css(KtaColors::BgSurface), Style::css(KtaColors::Border)));
    auto *layout = new QHBoxLayout(bar);
    layout->setContentsMargins(16, 16, 16, 0);
    layout->setSpacing(8);
    auto *titles = new QVBoxLayout;
    titles->setSpacing(2);
    titles->addWidget(label(title, 15, QFont::DemiBold, KtaColors::Text1, bar));
    titles->addWidget(label(subtitle, 11, QFont::Normal, KtaColors::Text3, bar));
    layout->addLayout(titles, 1);
    *search = searchField("Search", bar);
    layout->addWidget(*search);
    if (extra) layout->addWidget(extra);
    return bar;
}

static void setupTable(QTableView *view)
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
    view->horizontalHeader()->setDefaultAlignment(Qt::AlignLeft | Qt::AlignVCenter);
    view->horizontalHeader()->setFont(uiFont(10, QFont::DemiBold));
    QPalette p = view->palette();
    p.setColor(QPalette::Base, KtaColors::BgBase);
    p.setColor(QPalette::AlternateBase, KtaColors::BgAlt);
    p.setColor(QPalette::Highlight, KtaColors::Selection);
    p.setColor(QPalette::HighlightedText, KtaColors::Text1);
    view->setPalette(p);
}

ConnectionsTab::ConnectionsTab(QWidget *parent) : QWidget(parent)
{
    auto *layout = new QVBoxLayout(this);
    layout->setContentsMargins(0, 0, 0, 0);
    layout->setSpacing(0);

    auto *toggleWrap = new QWidget(this);
    toggleWrap->setStyleSheet("background:transparent;");
    auto *toggleLayout = new QHBoxLayout(toggleWrap);
    toggleLayout->setContentsMargins(0, 0, 0, 0);
    toggleLayout->setSpacing(8);
    auto *toggleLabel = label("Show inactive", 11, QFont::Normal, KtaColors::Text3, toggleWrap);
    m_showInactive = new ToggleSwitch(toggleWrap);
    toggleLayout->addWidget(toggleLabel);
    toggleLayout->addWidget(m_showInactive);
    layout->addWidget(topBar("Connections", "Live process-level socket activity", &m_filter, toggleWrap, this));

    auto *cards = new QWidget(this);
    auto *cardLayout = new QHBoxLayout(cards);
    cardLayout->setContentsMargins(24, 16, 24, 16);
    cardLayout->setSpacing(12);
    m_total = new StatCard("Total Connections", KtaColors::Text1, cards);
    m_inRate = new StatCard("Inbound Rate", KtaColors::Accent, cards);
    m_outRate = new StatCard("Outbound Rate", KtaColors::Amber, cards);
    m_processes = new StatCard("Processes", KtaColors::Text1, cards);
    for (auto *card : {m_total, m_inRate, m_outRate, m_processes}) cardLayout->addWidget(card, 1);
    layout->addWidget(cards);

    m_model = new TrafficModel(this);
    auto *proxy = new ConnectionProxy;
    proxy->setParent(this);
    m_proxy = proxy;
    m_proxy->setSourceModel(m_model);
    m_proxy->setFilterCaseSensitivity(Qt::CaseInsensitive);
    m_proxy->setFilterKeyColumn(-1);
    m_table = new QTableView(this);
    setupTable(m_table);
    m_table->setModel(m_proxy);
    m_table->setItemDelegateForColumn(TrafficModel::Pid, new MonoDelegate(KtaColors::Text3, m_table));
    m_table->setItemDelegateForColumn(TrafficModel::Protocol, new ProtoBadgeDelegate(m_table));
    m_table->setItemDelegateForColumn(TrafficModel::Local, new MonoDelegate(KtaColors::Text2, m_table));
    m_table->setItemDelegateForColumn(TrafficModel::Remote, new MonoDelegate(KtaColors::Text2, m_table));
    m_table->setItemDelegateForColumn(TrafficModel::Domain, new ColorTextDelegate(KtaColors::Purple, m_table));
    m_table->setItemDelegateForColumn(TrafficModel::State, new StateBadgeDelegate(m_table));
    m_table->setItemDelegateForColumn(TrafficModel::InBytes, new MonoDelegate(KtaColors::Text2, m_table));
    m_table->setItemDelegateForColumn(TrafficModel::OutBytes, new MonoDelegate(KtaColors::Text2, m_table));
    m_table->setItemDelegateForColumn(TrafficModel::InRate, new RateBarDelegate(KtaColors::Accent, m_table));
    m_table->setItemDelegateForColumn(TrafficModel::OutRate, new RateBarDelegate(KtaColors::Amber, m_table));
    m_table->horizontalHeader()->setSectionResizeMode(QHeaderView::Interactive);
    m_table->horizontalHeader()->resizeSection(TrafficModel::Process, 140);
    m_table->horizontalHeader()->resizeSection(TrafficModel::Local, 160);
    m_table->horizontalHeader()->resizeSection(TrafficModel::Remote, 160);
    layout->addWidget(m_table, 1);

    connect(m_filter, &QLineEdit::textChanged, m_proxy, &QSortFilterProxyModel::setFilterFixedString);
    connect(m_showInactive, &ToggleSwitch::toggled, this, [this](bool on) {
        static_cast<ConnectionProxy *>(m_proxy)->showInactive = on;
        m_proxy->invalidate();
    });
}

void ConnectionsTab::updateData(const QVector<TrafficEntry> &entries)
{
    m_model->updateData(entries);
    quint64 in = 0, out = 0;
    QSet<int> pids;
    int active = 0;
    for (const auto &e : entries) {
        in += e.rateInBps;
        out += e.rateOutBps;
        if (e.pid > 0) pids.insert(e.pid);
        if (e.isActive()) ++active;
    }
    m_total->setValue(QString::number(entries.size()));
    m_total->setSubtext(QString("%1 active").arg(active));
    m_inRate->setValue(formatRate(in));
    m_inRate->setSubtext(formatBytes(std::accumulate(entries.begin(), entries.end(), qint64(0), [](qint64 s, const TrafficEntry &e) { return s + e.bytesIn; })));
    m_outRate->setValue(formatRate(out));
    m_outRate->setSubtext(formatBytes(std::accumulate(entries.begin(), entries.end(), qint64(0), [](qint64 s, const TrafficEntry &e) { return s + e.bytesOut; })));
    m_processes->setValue(QString::number(pids.size()));
    m_processes->setSubtext("with network activity");
}

#include "ConnectionsTab.moc"
