#pragma once
#include <QWidget>
#include <QTableView>
#include <QLineEdit>
#include <QLabel>
#include <QSortFilterProxyModel>
#include "../core/ProcModel.h"
#include "../core/ProcEntry.h"

class ProcessesTab : public QWidget
{
    Q_OBJECT
public:
    explicit ProcessesTab(QWidget *parent = nullptr);
    void updateData(const QVector<ProcEntry> &entries);
signals:
    void processClicked(int pid, const QString &process, const QString &exe);
private slots:
    void onRowClicked(const QModelIndex &index);
    void onFilterChanged(const QString &text);
private:
    QTableView            *m_table;
    ProcModel             *m_model;
    QSortFilterProxyModel *m_proxy;
    QLineEdit             *m_filterEdit;
    QLabel                *m_countLabel;
};
