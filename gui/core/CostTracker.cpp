#include "CostTracker.h"
#include <QStandardPaths>
#include <QDir>
#include <QFile>
#include <QJsonDocument>
#include <QJsonObject>
#include <QDateTime>
#include <QDate>

CostTracker &CostTracker::instance()
{
    static CostTracker inst;
    return inst;
}

CostTracker::CostTracker(QObject *parent) : QObject(parent)
{
    loadSettings();
}

QString CostTracker::settingsPath() const
{
    QString dir = QStandardPaths::writableLocation(
        QStandardPaths::AppLocalDataLocation);
    QDir().mkpath(dir);
    return dir + "/settings.json";
}

void CostTracker::loadSettings()
{
    QFile f(settingsPath());
    if (!f.open(QIODevice::ReadOnly)) return;
    QJsonObject obj = QJsonDocument::fromJson(f.readAll()).object();
    m_rate  = obj.value("isp_rate_inr_per_gb").toDouble(10.0);
    m_limit = obj.value("monthly_limit_gb").toDouble(100.0);
}

void CostTracker::saveSettings(double rateInrPerGb, double limitGb)
{
    m_rate  = rateInrPerGb;
    m_limit = limitGb;
    QJsonObject obj;
    obj["isp_rate_inr_per_gb"] = m_rate;
    obj["monthly_limit_gb"]    = m_limit;
    QFile f(settingsPath());
    if (f.open(QIODevice::WriteOnly))
        f.write(QJsonDocument(obj).toJson());
}

double CostTracker::bytesToInr(quint64 bytes) const
{
    double gb = bytes / (1024.0 * 1024.0 * 1024.0);
    return gb * m_rate;
}

MonthlySummary CostTracker::getMonthlySummary()
{
    MonthlySummary s;
    s.rateInrPerGb = m_rate;
    s.limitGB      = m_limit;

    // Sum this month's usage from daily_totals
    QString monthStart = QDate(QDate::currentDate().year(),
                               QDate::currentDate().month(), 1)
                             .toString("yyyy-MM-dd");
    auto totals = HistoryDB::instance().getAllDailyTotals(31);
    for (const auto &d : totals) {
        if (d.date >= monthStart) {
            s.usedBytes += d.totalOut + d.totalIn;
        }
    }
    s.usedGB   = s.usedBytes / (1024.0*1024.0*1024.0);
    s.costInr  = s.usedGB * m_rate;
    s.pctUsed  = (s.limitGB > 0) ? (s.usedGB / s.limitGB * 100.0) : 0.0;

    QDate today = QDate::currentDate();
    QDate monthEnd = QDate(today.year(), today.month(),
                           today.daysInMonth());
    s.daysLeft = today.daysTo(monthEnd);
    return s;
}

QVector<ProcessCost> CostTracker::getProcessCosts(int days)
{
    QVector<ProcessCost> result;
    QStringList procs = HistoryDB::instance().getProcessList();

    quint64 totalAll = 0;

    for (const QString &proc : procs) {
        auto daily = HistoryDB::instance().getDailyTotals(proc, days);
        if (daily.isEmpty()) continue;

        ProcessCost pc;
        pc.process = proc;

        QString today = QDate::currentDate().toString("yyyy-MM-dd");
        QString weekAgo = QDate::currentDate().addDays(-7)
                              .toString("yyyy-MM-dd");

        for (const auto &d : daily) {
            quint64 bytes = d.totalOut + d.totalIn;
            pc.totalBytes += bytes;
            if (d.date == today)    pc.todayBytes += bytes;
            if (d.date >= weekAgo)  pc.weekBytes  += bytes;
        }

        pc.todayCostInr = bytesToInr(pc.todayBytes);
        pc.weekCostInr  = bytesToInr(pc.weekBytes);
        pc.totalCostInr = bytesToInr(pc.totalBytes);

        totalAll += pc.totalBytes;
        result.append(pc);
    }

    // Compute percentage
    for (auto &pc : result)
        pc.pctOfUsage = totalAll > 0 ?
            (pc.totalBytes * 100.0 / totalAll) : 0.0;

    // Sort by total cost descending
    std::sort(result.begin(), result.end(),
        [](const ProcessCost &a, const ProcessCost &b) {
            return a.totalCostInr > b.totalCostInr;
        });

    return result;
}

QVector<DailyTotal> CostTracker::getDailyCosts(int days)
{
    return HistoryDB::instance().getAllDailyTotals(days);
}
