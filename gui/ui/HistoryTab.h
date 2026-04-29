#pragma once
#include <QWidget>
#include "../core/HistoryDB.h"
class QAbstractTableModel;
class QSpinBox;

class HistoryTab : public QWidget
{
    Q_OBJECT
public:
    explicit HistoryTab(QWidget *parent = nullptr);
    void refresh();
private:
    QSpinBox *m_days = nullptr;
    QAbstractTableModel *m_processModel = nullptr;
};
