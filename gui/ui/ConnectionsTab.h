#pragma once
#include <QWidget>
#include <QTableView>
#include <QLineEdit>
#include <QComboBox>
#include <QLabel>
#include <QSplitter>
#include <QSortFilterProxyModel>
#include "../core/TrafficModel.h"
#include "../core/TrafficEntry.h"

class DetailPanel : public QWidget
{
    Q_OBJECT
public:
    explicit DetailPanel(QWidget *parent = nullptr);
    void showEntry(const TrafficEntry &e);
    void clear();
private:
    QLabel *m_process;
    QLabel *m_statOut;
    QLabel *m_statIn;
    QLabel *m_statBytes;
    QLabel *m_statDuration;
    QLabel *m_domain;
    QLabel *m_route;
};

class ConnectionsTab : public QWidget
{
    Q_OBJECT
public:
    explicit ConnectionsTab(QWidget *parent = nullptr);
    void updateData(const QVector<TrafficEntry> &entries);
signals:
    void processClicked(int pid, const QString &process);
private slots:
    void onRowClicked(const QModelIndex &index);
    void onFilterChanged(const QString &text);
    void onStateFilterChanged(int index);
private:
    QSplitter             *m_splitter;
    QTableView            *m_table;
    TrafficModel          *m_model;
    QSortFilterProxyModel *m_proxy;
    QLineEdit             *m_filterEdit;
    QComboBox             *m_stateFilter;
    QLabel                *m_countLabel;
    DetailPanel           *m_detail;
};
