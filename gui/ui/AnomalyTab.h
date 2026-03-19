#pragma once
#include <QWidget>
#include <QTableWidget>
#include <QLabel>
#include "../core/AnomalyEntry.h"

class AnomalyTab : public QWidget
{
    Q_OBJECT
public:
    explicit AnomalyTab(QWidget *parent = nullptr);
    void updateData(const QVector<AnomalyEntry> &entries);
private:
    QTableWidget *m_table;
    QLabel       *m_countLabel;
    QLabel       *m_noDataLabel;
};
