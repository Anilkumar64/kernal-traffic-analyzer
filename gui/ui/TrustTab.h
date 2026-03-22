#pragma once
#include <QWidget>
#include <QTableWidget>
#include <QLabel>
#include "../core/TrustScorer.h"
#include "../core/ProcEntry.h"
#include "../core/TrafficEntry.h"

class TrustTab : public QWidget
{
    Q_OBJECT
public:
    explicit TrustTab(QWidget *parent = nullptr);
    void updateData(const QVector<ProcEntry> &procs,
                    const QVector<TrafficEntry> &conns);

private:
    QTableWidget *m_table;
    QLabel *m_summary;
};