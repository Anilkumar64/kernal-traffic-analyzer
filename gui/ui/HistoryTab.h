#pragma once

#include <QWidget>
#include "../core/HistoryDB.h"

class BandwidthChart;
class QAbstractTableModel;
class QComboBox;

class HistoryTab : public QWidget
{
    Q_OBJECT
public:
    explicit HistoryTab(QWidget *parent = nullptr);
    void refresh();
private:
    QComboBox *m_days = nullptr;
    QAbstractTableModel *m_processModel = nullptr;
    BandwidthChart *m_chart = nullptr;
};
