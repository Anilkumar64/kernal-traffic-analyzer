#pragma once

#include <QWidget>
#include "../core/AnomalyEntry.h"

class AnomalyModel;
class QSortFilterProxyModel;
class QStackedWidget;
class QTableView;

class AnomalyTab : public QWidget
{
    Q_OBJECT
public:
    explicit AnomalyTab(QWidget *parent = nullptr);
    void updateData(const QVector<AnomalyEntry> &entries);
    int count() const;
private:
    AnomalyModel *m_model = nullptr;
    QSortFilterProxyModel *m_proxy = nullptr;
    QStackedWidget *m_stack = nullptr;
    QTableView *m_table = nullptr;
};
