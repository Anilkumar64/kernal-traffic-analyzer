#pragma once
#include <QWidget>
#include <QLabel>
#include <QDoubleSpinBox>
#include <QTableWidget>
#include <QProgressBar>
#include <QTimer>
#include "../core/CostTracker.h"

class CostBarChart : public QWidget
{
    Q_OBJECT
public:
    explicit CostBarChart(QWidget *parent = nullptr);
    void setData(const QVector<DailyTotal> &totals, double rateInrPerGb);

protected:
    void paintEvent(QPaintEvent *) override;
    void mouseMoveEvent(QMouseEvent *) override;

private:
    QVector<DailyTotal> m_totals;
    double m_rate = 10.0;
    int    m_hoverIdx = -1;
};

class CostTab : public QWidget
{
    Q_OBJECT
public:
    explicit CostTab(QWidget *parent = nullptr);
    void refresh();

private slots:
    void onSave();

private:
    void updateSummary();
    void updateTable();
    void updateChart();

    // Settings
    QDoubleSpinBox *m_rateSpinBox;
    QDoubleSpinBox *m_limitSpinBox;

    // Summary cards
    QLabel     *m_cardUsed;
    QLabel     *m_cardCost;
    QLabel     *m_cardRemaining;
    QLabel     *m_cardDaysLeft;
    QProgressBar *m_usageBar;

    // Table
    QTableWidget *m_table;

    // Chart
    CostBarChart *m_chart;

    QTimer *m_timer;
};
