#pragma once

#include <QWidget>
#include "../core/ProcReader.h"

class QAbstractTableModel;
class QGridLayout;
class QSortFilterProxyModel;

class NetworkPerfTab : public QWidget
{
    Q_OBJECT
public:
    explicit NetworkPerfTab(QWidget *parent = nullptr);
    void updateData(const ProcSnapshot &snap);
private:
    QAbstractTableModel *m_model = nullptr;
    QSortFilterProxyModel *m_proxy = nullptr;
    QGridLayout *m_cards = nullptr;
};
