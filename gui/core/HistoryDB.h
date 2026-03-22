#pragma once
#include <QString>
#include <QVector>
#include <QObject>
#include <QMutex>

struct BwSample {
    qint64  ts     = 0;
    int     pid    = 0;
    QString process;
    quint32 outBps = 0;
    quint32 inBps  = 0;
    quint64 outBytes = 0;
    quint64 inBytes  = 0;
};

struct DailyTotal {
    QString date;      // "YYYY-MM-DD"
    QString process;
    quint64 totalOut = 0;
    quint64 totalIn  = 0;
    double  costInr  = 0.0;
};

class HistoryDB : public QObject
{
    Q_OBJECT
public:
    static HistoryDB &instance();

    bool    open();
    void    close();

    void    insertSample(const BwSample &s);
    void    insertSamples(const QVector<BwSample> &samples);

    QVector<BwSample>   getLastHour(const QString &process);
    QVector<BwSample>   getLast24h(const QString &process);
    QVector<DailyTotal> getDailyTotals(const QString &process, int days = 7);
    QVector<DailyTotal> getAllDailyTotals(int days = 30);
    QStringList         getProcessList();

    void    prune();  // delete samples older than 7 days

private:
    explicit HistoryDB(QObject *parent = nullptr);
    ~HistoryDB();

    void    execSQL(const QString &sql);
    bool    m_open = false;
    void   *m_db   = nullptr; // sqlite3*
    QMutex  m_mutex;
};
