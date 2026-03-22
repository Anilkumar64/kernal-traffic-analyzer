#pragma once
#include <QPushButton>
#include <QWidget>
#include <QTableWidget>
#include <QLabel>
#include "../core/BgpMonitor.h"

class BgpTab : public QWidget
{
    Q_OBJECT
public:
    explicit BgpTab(QWidget *parent = nullptr);
    void setMonitor(BgpMonitor *monitor);

public slots:
    void onDataChanged();

private:
    void rebuild();

    BgpMonitor   *m_monitor = nullptr;
    QLabel       *m_statusBanner;
    QLabel       *m_learningLabel;
    QTableWidget *m_learnedTable;
    QTableWidget *m_alertTable;
    QPushButton  *m_resetBtn;
};
