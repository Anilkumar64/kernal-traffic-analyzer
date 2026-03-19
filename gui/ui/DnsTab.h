#pragma once
#include <QWidget>
#include <QTableWidget>
#include <QLabel>
#include "../core/DnsEntry.h"

class DnsTab : public QWidget
{
    Q_OBJECT
public:
    explicit DnsTab(QWidget *parent = nullptr);
    void updateData(const QVector<DnsEntry> &entries);
private:
    QTableWidget *m_table;
    QLabel       *m_countLabel;
};
