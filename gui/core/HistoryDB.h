#pragma once
#include <QString>
#include <QVector>
#include <QObject>
#include <QMutex>
#include <QHash>

// ============================================================
// Data structures
// ============================================================

struct BwSample
{
    qint64 ts = 0;
    int pid = 0;
    QString process;
    quint32 outBps = 0;
    quint32 inBps = 0;
    quint64 outBytes = 0;
    quint64 inBytes = 0;
};

struct DailyTotal
{
    QString date; // "YYYY-MM-DD"
    QString process;
    quint64 totalOut = 0;
    quint64 totalIn = 0;
    double costInr = 0.0;
};

// ============================================================
// HistoryDB — SQLite-backed bandwidth history store.
//
// Thread-safety: all public methods acquire m_mutex internally.
// Callers must NOT hold m_mutex when calling any public method —
// use the private pruneUnlocked() for internal calls that already
// hold the lock (e.g. from open()).
// ============================================================

class HistoryDB : public QObject
{
    Q_OBJECT

public:
    static HistoryDB &instance();

    bool open();
    void close();

    void insertSample(const BwSample &s);
    void insertSamples(const QVector<BwSample> &samples);

    QVector<BwSample> getLastHour(const QString &process);
    QVector<BwSample> getLast24h(const QString &process);
    QVector<DailyTotal> getDailyTotals(const QString &process, int days = 7);
    QVector<DailyTotal> getAllDailyTotals(int days = 30);
    QStringList getProcessList();

    void prune(); // delete samples older than 7 days (acquires lock)

private:
    explicit HistoryDB(QObject *parent = nullptr);
    ~HistoryDB();

    // Helpers — callers must already hold m_mutex
    void execSQL(const QString &sql);
    void pruneUnlocked(); // prune without acquiring m_mutex

    bool m_open = false;
    void *m_db = nullptr; // sqlite3 *
    QMutex m_mutex;

    struct PreviousBytes {
        quint64 outBytes = 0;
        quint64 inBytes = 0;
        bool valid = false;
    };
    QHash<QString, PreviousBytes> m_previousBytes;
};
