#pragma once
#include <QObject>
#include <QString>
#include <QVector>
#include "HistoryDB.h"

struct ProcessCost {
    QString process;
    quint64 todayBytes   = 0;
    quint64 weekBytes    = 0;
    quint64 totalBytes   = 0;
    double  todayCostInr = 0.0;
    double  weekCostInr  = 0.0;
    double  totalCostInr = 0.0;
    double  pctOfUsage   = 0.0;
};

struct MonthlySummary {
    quint64 usedBytes    = 0;
    double  usedGB       = 0.0;
    double  limitGB      = 100.0;
    double  costInr      = 0.0;
    double  rateInrPerGb = 10.0;
    int     daysLeft     = 0;
    double  pctUsed      = 0.0;
};

class CostTracker : public QObject
{
    Q_OBJECT
public:
    static CostTracker &instance();

    void   loadSettings();
    void   saveSettings(double rateInrPerGb, double limitGb);

    double rateInrPerGb() const { return m_rate; }
    double limitGb()      const { return m_limit; }

    double bytesToInr(quint64 bytes) const;

    MonthlySummary       getMonthlySummary();
    QVector<ProcessCost> getProcessCosts(int days = 30);
    QVector<DailyTotal>  getDailyCosts(int days = 30);

private:
    explicit CostTracker(QObject *parent = nullptr);
    QString settingsPath() const;

    double m_rate  = 10.0;  // ₹ per GB
    double m_limit = 100.0; // GB per month
};
