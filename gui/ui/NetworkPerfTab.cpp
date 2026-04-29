#include "NetworkPerfTab.h"
#include <QAbstractTableModel>
#include <QHeaderView>
#include <QTableView>
#include <QVBoxLayout>

class PerfModel : public QAbstractTableModel {
public:
    int rowCount(const QModelIndex & = {}) const override { return 1; }
    int columnCount(const QModelIndex & = {}) const override { return 5; }
    QVariant data(const QModelIndex &index, int role) const override {
        if (!index.isValid() || role != Qt::DisplayRole) return {};
        if (index.column() == 0) return "—";
        // TODO(rebuild): the kernel module does not expose interface-level RTT, jitter, or loss.
        return "—";
    }
    QVariant headerData(int section, Qt::Orientation orientation, int role) const override {
        if (orientation != Qt::Horizontal || role != Qt::DisplayRole) return {};
        static const QStringList headers = {"INTERFACE", "RTT (MS)", "JITTER (MS)", "PACKET LOSS %", "LAST UPDATED"};
        return headers.value(section);
    }
};

NetworkPerfTab::NetworkPerfTab(QWidget *parent) : QWidget(parent)
{
    auto *layout = new QVBoxLayout(this);
    m_model = new PerfModel;
    m_model->setParent(this);
    auto *table = new QTableView(this);
    table->setModel(m_model);
    table->setAlternatingRowColors(true);
    table->setShowGrid(false);
    table->verticalHeader()->setDefaultSectionSize(36);
    table->verticalHeader()->hide();
    table->horizontalHeader()->setSectionResizeMode(QHeaderView::Interactive);
    layout->addWidget(table, 1);
}

void NetworkPerfTab::updateData(const ProcSnapshot &) {}
