#include "ProcessesTab.h"
#include "Style.h"
#include "delegates/ColorTextDelegate.h"
#include "delegates/MonoDelegate.h"
#include "delegates/RateBarDelegate.h"

#include <QAction>
#include <QAbstractItemModel>
#include <QHeaderView>
#include <QLabel>
#include <QLineEdit>
#include <QPainter>
#include <QSortFilterProxyModel>
#include <QTreeView>
#include <QVBoxLayout>

class ProcessTreeModel : public QAbstractItemModel
{
public:
    enum Column { Pid, Process, Exe, Connections, InTotal, OutTotal, InRate, OutRate, Count };
    explicit ProcessTreeModel(QObject *parent = nullptr) : QAbstractItemModel(parent) {}
    static constexpr quintptr ChildFlag = quintptr(1) << (sizeof(quintptr) * 8 - 1);
    static bool isChildId(quintptr id) { return (id & ChildFlag) != 0; }
    static int topRowFromId(quintptr id) { return int(id - 1); }
    static int parentRowFromChildId(quintptr id) { return int((id & ~ChildFlag) >> 32); }
    static int childRowFromId(quintptr id) { return int(id & 0xffffffffu); }
    QModelIndex index(int row, int column, const QModelIndex &parent = {}) const override
    {
        if (!hasIndex(row, column, parent)) return {};
        if (!parent.isValid()) return createIndex(row, column, quintptr(row + 1));
        const quintptr parentId = parent.internalId();
        if (!isChildId(parentId))
            return createIndex(row, column, ChildFlag | (quintptr(topRowFromId(parentId)) << 32) | quintptr(row));
        return {};
    }
    QModelIndex parent(const QModelIndex &idx) const override
    {
        if (!idx.isValid()) return {};
        const quintptr id = idx.internalId();
        if (!isChildId(id)) return {};
        const int parentRow = parentRowFromChildId(id);
        return createIndex(parentRow, 0, quintptr(parentRow + 1));
    }
    int rowCount(const QModelIndex &parent = {}) const override
    {
        if (!parent.isValid()) return m_processes.size();
        const quintptr id = parent.internalId();
        if (isChildId(id)) return 0;
        return m_children.value(m_processes.value(topRowFromId(id)).pid).size();
    }
    int columnCount(const QModelIndex & = {}) const override { return Count; }
    QVariant data(const QModelIndex &idx, int role) const override
    {
        if (!idx.isValid()) return {};
        const quintptr id = idx.internalId();
        if (!isChildId(id)) {
            const auto &p = m_processes.at(topRowFromId(id));
            if (role == Qt::DisplayRole) {
                switch (idx.column()) {
                case Pid: return p.pid;
                case Process: return p.process;
                case Exe: return p.exe;
                case Connections: return p.totalConns;
                case InTotal: return p.formatBytes(p.bytesIn);
                case OutTotal: return p.formatBytes(p.bytesOut);
                case InRate: return p.formatRate(p.rateInBps);
                case OutRate: return p.formatRate(p.rateOutBps);
                default: return {};
                }
            }
            if (role == Qt::FontRole && idx.column() == Process) return uiFont(13, QFont::Medium);
            if (role == Qt::TextAlignmentRole && idx.column() >= Connections) return int(Qt::AlignRight | Qt::AlignVCenter);
            return {};
        }
        const auto list = m_children.value(m_processes.value(parentRowFromChildId(id)).pid);
        const int childRow = childRowFromId(id);
        if (childRow >= list.size()) return {};
        const auto &c = list.at(childRow);
        if (role == Qt::DisplayRole) {
            switch (idx.column()) {
            case Pid: return {};
            case Process: return QString("%1").arg(c.protocol.toUpper());
            case Exe: return QString("%1:%2").arg(c.srcIp).arg(c.srcPort);
            case Connections: return QString("%1:%2").arg(c.destIp).arg(c.destPort);
            case InTotal: return c.domain == "-" ? QString() : c.domain;
            case OutTotal: return c.stateString();
            case InRate: return c.formatBytes(c.bytesIn);
            case OutRate: return c.formatBytes(c.bytesOut);
            default: return {};
            }
        }
        if (role == Qt::ForegroundRole) return KtaColors::Text3;
        return {};
    }
    QVariant headerData(int section, Qt::Orientation orientation, int role) const override
    {
        if (orientation != Qt::Horizontal || role != Qt::DisplayRole) return {};
        static const QStringList headers = {"PID", "PROCESS", "EXE PATH", "CONNS", "IN (TOTAL)", "OUT (TOTAL)", "IN RATE", "OUT RATE"};
        return headers.value(section);
    }
    void setData(QVector<ProcEntry> procs, QVector<TrafficEntry> conns)
    {
        beginResetModel();
        m_processes = std::move(procs);
        m_children.clear();
        for (const auto &c : conns) m_children[c.pid].append(c);
        endResetModel();
    }
private:
    QVector<ProcEntry> m_processes;
    QHash<int, QVector<TrafficEntry>> m_children;
};

class ProcessDelegate : public QStyledItemDelegate
{
public:
    explicit ProcessDelegate(QObject *parent = nullptr) : QStyledItemDelegate(parent) {}
    void initStyleOption(QStyleOptionViewItem *option, const QModelIndex &index) const override
    {
        QStyledItemDelegate::initStyleOption(option, index);
        option->state &= ~QStyle::State_HasFocus;
    }
    QSize sizeHint(const QStyleOptionViewItem &, const QModelIndex &) const override { return {-1, 36}; }
    void paint(QPainter *p, const QStyleOptionViewItem &option, const QModelIndex &index) const override
    {
        QStyleOptionViewItem opt(option);
        initStyleOption(&opt, index);
        p->save();
        QStyledItemDelegate::paint(p, opt, index);
        if (!index.parent().isValid() && index.column() == ProcessTreeModel::Process) {
            p->setPen(KtaColors::Text3);
            p->drawText(QRect(opt.rect.left() + 6, opt.rect.top(), 14, opt.rect.height()), Qt::AlignCenter, option.state & QStyle::State_Open ? "v" : ">");
        }
        p->restore();
    }
};

static QLabel *titleLabel(const QString &text, int px, int weight, const QColor &color, QWidget *parent)
{
    auto *l = new QLabel(text, parent);
    l->setFont(uiFont(px, weight));
    l->setStyleSheet(QString("color:%1;background:transparent;").arg(Style::css(color)));
    return l;
}

static QWidget *topBar(QLineEdit **search, QWidget *parent)
{
    auto *bar = new QWidget(parent);
    bar->setFixedHeight(62);
    bar->setStyleSheet(QString("background:%1;border-bottom:1px solid %2;").arg(Style::css(KtaColors::BgSurface), Style::css(KtaColors::Border)));
    auto *layout = new QHBoxLayout(bar);
    layout->setContentsMargins(16, 16, 16, 0);
    auto *titles = new QVBoxLayout;
    titles->setSpacing(2);
    titles->addWidget(titleLabel("Processes", 15, QFont::DemiBold, KtaColors::Text1, bar));
    titles->addWidget(titleLabel("Process rollups with inline connection details", 11, QFont::Normal, KtaColors::Text3, bar));
    layout->addLayout(titles, 1);
    *search = new QLineEdit(bar);
    (*search)->setFixedWidth(220);
    (*search)->setPlaceholderText("Search");
    (*search)->addAction(new QAction(QString::fromUtf8("\342\214\225"), *search), QLineEdit::LeadingPosition);
    layout->addWidget(*search);
    return bar;
}

ProcessesTab::ProcessesTab(QWidget *parent) : QWidget(parent)
{
    auto *layout = new QVBoxLayout(this);
    layout->setContentsMargins(0, 0, 0, 0);
    layout->setSpacing(0);
    layout->addWidget(topBar(&m_filter, this));
    m_model = new ProcessTreeModel(this);
    m_proxy = new QSortFilterProxyModel(this);
    m_proxy->setSourceModel(m_model);
    m_proxy->setFilterCaseSensitivity(Qt::CaseInsensitive);
    m_proxy->setFilterKeyColumn(-1);
    m_proxy->setRecursiveFilteringEnabled(true);
    m_tree = new QTreeView(this);
    m_tree->setModel(m_proxy);
    m_tree->setRootIsDecorated(false);
    m_tree->setItemsExpandable(true);
    m_tree->setExpandsOnDoubleClick(false);
    m_tree->setAlternatingRowColors(true);
    m_tree->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_tree->setSelectionMode(QAbstractItemView::SingleSelection);
    m_tree->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_tree->setFocusPolicy(Qt::NoFocus);
    m_tree->setSortingEnabled(true);
    m_tree->header()->setDefaultAlignment(Qt::AlignLeft | Qt::AlignVCenter);
    m_tree->header()->setSectionResizeMode(QHeaderView::Interactive);
    m_tree->setItemDelegate(new ProcessDelegate(m_tree));
    m_tree->setItemDelegateForColumn(ProcessTreeModel::Pid, new MonoDelegate(KtaColors::Text3, m_tree));
    m_tree->setItemDelegateForColumn(ProcessTreeModel::InRate, new RateBarDelegate(KtaColors::Accent, m_tree));
    m_tree->setItemDelegateForColumn(ProcessTreeModel::OutRate, new RateBarDelegate(KtaColors::Amber, m_tree));
    layout->addWidget(m_tree, 1);
    connect(m_filter, &QLineEdit::textChanged, m_proxy, &QSortFilterProxyModel::setFilterFixedString);
    connect(m_tree, &QTreeView::clicked, this, [this](const QModelIndex &idx) {
        if (!idx.isValid() || idx.parent().isValid()) return;
        m_tree->isExpanded(idx) ? m_tree->collapse(idx) : m_tree->expand(idx);
    });
}

void ProcessesTab::updateData(const QVector<ProcEntry> &processes, const QVector<TrafficEntry> &connections)
{
    m_model->setData(processes, connections);
}
