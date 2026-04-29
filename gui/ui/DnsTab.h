#pragma once

#include <QWidget>
#include "../core/DnsEntry.h"

class DnsModel;
class QLineEdit;
class QSortFilterProxyModel;
class QTableView;

class DnsTab : public QWidget
{
    Q_OBJECT
public:
    explicit DnsTab(QWidget *parent = nullptr);
    void updateData(const QVector<DnsEntry> &entries);
private:
    DnsModel *m_model = nullptr;
    QSortFilterProxyModel *m_proxy = nullptr;
    QTableView *m_table = nullptr;
};
