#include "HistoryDB.h"
#include <sqlite3.h>
#include <QStandardPaths>
#include <QDir>
#include <QDate>
#include <QDateTime>
#include <QMutexLocker>
#include <QDebug>

// ============================================================
// Singleton
// ============================================================

HistoryDB &HistoryDB::instance()
{
    static HistoryDB inst;
    return inst;
}

HistoryDB::HistoryDB(QObject *parent) : QObject(parent) {}

HistoryDB::~HistoryDB()
{
    close();
}

// ============================================================
// open / close
// ============================================================

bool HistoryDB::open()
{
    QMutexLocker lock(&m_mutex);

    if (m_open)
        return true;

    QString dir = QStandardPaths::writableLocation(
        QStandardPaths::AppLocalDataLocation);
    QDir().mkpath(dir);
    QString path = dir + "/history.db";

    int rc = sqlite3_open(path.toUtf8().constData(),
                          reinterpret_cast<sqlite3 **>(&m_db));
    if (rc != SQLITE_OK)
    {
        qWarning() << "HistoryDB: cannot open" << path;
        return false;
    }

    // WAL mode for better concurrent writes
    execSQL("PRAGMA journal_mode=WAL;");
    execSQL("PRAGMA synchronous=NORMAL;");

    execSQL(R"(
        CREATE TABLE IF NOT EXISTS bw_samples (
            ts        INTEGER NOT NULL,
            pid       INTEGER NOT NULL,
            process   TEXT    NOT NULL,
            out_bps   INTEGER NOT NULL DEFAULT 0,
            in_bps    INTEGER NOT NULL DEFAULT 0,
            out_bytes INTEGER NOT NULL DEFAULT 0,
            in_bytes  INTEGER NOT NULL DEFAULT 0
        );
    )");
    execSQL("CREATE INDEX IF NOT EXISTS idx_ts   ON bw_samples(ts);");
    execSQL("CREATE INDEX IF NOT EXISTS idx_proc ON bw_samples(process, ts);");

    execSQL(R"(
        CREATE TABLE IF NOT EXISTS daily_totals (
            date      TEXT NOT NULL,
            process   TEXT NOT NULL,
            total_out INTEGER NOT NULL DEFAULT 0,
            total_in  INTEGER NOT NULL DEFAULT 0,
            PRIMARY KEY (date, process)
        );
    )");

    m_open = true;

    /*
     * IMPORTANT: call pruneUnlocked() here, NOT prune().
     * prune() would try to acquire m_mutex which we already hold
     * → non-recursive QMutex deadlock → process hangs forever.
     */
    pruneUnlocked();

    return true;
}

void HistoryDB::close()
{
    QMutexLocker lock(&m_mutex);

    if (m_db)
    {
        sqlite3_close(reinterpret_cast<sqlite3 *>(m_db));
        m_db = nullptr;
    }
    m_open = false;
}

// ============================================================
// Internal helpers  (caller must hold m_mutex)
// ============================================================

void HistoryDB::execSQL(const QString &sql)
{
    if (!m_db)
        return;

    char *errmsg = nullptr;
    sqlite3_exec(reinterpret_cast<sqlite3 *>(m_db),
                 sql.toUtf8().constData(),
                 nullptr, nullptr, &errmsg);
    if (errmsg)
    {
        qWarning() << "HistoryDB SQL error:" << errmsg;
        sqlite3_free(errmsg);
    }
}

/*
 * pruneUnlocked — delete stale rows.
 * Must only be called when m_mutex is already held by the caller.
 */
void HistoryDB::pruneUnlocked()
{
    if (!m_db)
        return;

    sqlite3 *db = reinterpret_cast<sqlite3 *>(m_db);

    // Remove raw samples older than 7 days
    {
        qint64 cutoff = QDateTime::currentSecsSinceEpoch() - 7 * 86400;
        const char *sql = "DELETE FROM bw_samples WHERE ts < ?;";
        sqlite3_stmt *stmt = nullptr;
        if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) == SQLITE_OK && stmt)
        {
            sqlite3_bind_int64(stmt, 1, cutoff);
            sqlite3_step(stmt);
            sqlite3_finalize(stmt);
        }
    }

    // Remove daily totals older than 30 days
    {
        QString dateCutoff =
            QDate::currentDate().addDays(-30).toString("yyyy-MM-dd");
        const char *sql = "DELETE FROM daily_totals WHERE date < ?;";
        sqlite3_stmt *stmt = nullptr;
        if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) == SQLITE_OK && stmt)
        {
            sqlite3_bind_text(stmt, 1,
                              dateCutoff.toUtf8().constData(),
                              -1, SQLITE_TRANSIENT);
            sqlite3_step(stmt);
            sqlite3_finalize(stmt);
        }
    }
}

// ============================================================
// Public prune  (acquires lock itself — for external callers)
// ============================================================

void HistoryDB::prune()
{
    QMutexLocker lock(&m_mutex);
    pruneUnlocked();
}

// ============================================================
// insertSamples
// ============================================================

void HistoryDB::insertSample(const BwSample &s)
{
    insertSamples({s});
}

void HistoryDB::insertSamples(const QVector<BwSample> &samples)
{
    if (samples.isEmpty())
        return;

    QMutexLocker lock(&m_mutex);

    if (!m_open)
        return;

    sqlite3 *db = reinterpret_cast<sqlite3 *>(m_db);
    sqlite3_exec(db, "BEGIN TRANSACTION;", nullptr, nullptr, nullptr);

    // Insert raw samples
    {
        const char *sql =
            "INSERT INTO bw_samples"
            "(ts, pid, process, out_bps, in_bps, out_bytes, in_bytes)"
            " VALUES(?, ?, ?, ?, ?, ?, ?);";
        sqlite3_stmt *stmt = nullptr;
        if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK || !stmt)
        {
            qWarning() << "HistoryDB: prepare failed (insertSamples):"
                       << sqlite3_errmsg(db);
            sqlite3_exec(db, "ROLLBACK;", nullptr, nullptr, nullptr);
            return;
        }

        for (const auto &s : samples)
        {
            sqlite3_bind_int64(stmt, 1, s.ts);
            sqlite3_bind_int(stmt, 2, s.pid);
            sqlite3_bind_text(stmt, 3, s.process.toUtf8().constData(),
                              -1, SQLITE_TRANSIENT);
            sqlite3_bind_int64(stmt, 4, s.outBps);
            sqlite3_bind_int64(stmt, 5, s.inBps);
            sqlite3_bind_int64(stmt, 6, s.outBytes);
            sqlite3_bind_int64(stmt, 7, s.inBytes);
            sqlite3_step(stmt);
            sqlite3_reset(stmt);
        }
        sqlite3_finalize(stmt);
    }

    // Upsert daily totals
    {
        const char *upsert =
            "INSERT INTO daily_totals(date, process, total_out, total_in)"
            " VALUES(?, ?, ?, ?)"
            " ON CONFLICT(date, process) DO UPDATE SET"
            "   total_out = total_out + excluded.total_out,"
            "   total_in  = total_in  + excluded.total_in;";
        sqlite3_stmt *stmt = nullptr;
        if (sqlite3_prepare_v2(db, upsert, -1, &stmt, nullptr) != SQLITE_OK || !stmt)
        {
            qWarning() << "HistoryDB: prepare failed (upsert):"
                       << sqlite3_errmsg(db);
            sqlite3_exec(db, "COMMIT;", nullptr, nullptr, nullptr);
            return;
        }

        QString today =
            QDateTime::currentDateTime().toString("yyyy-MM-dd");
        for (const auto &s : samples)
        {
            QString key = QString("%1|%2").arg(s.pid).arg(s.process);
            PreviousBytes prev = m_previousBytes.value(key);
            quint64 deltaOut = s.outBytes;
            quint64 deltaIn = s.inBytes;

            if (prev.valid) {
                deltaOut = (s.outBytes >= prev.outBytes)
                    ? (s.outBytes - prev.outBytes)
                    : s.outBytes;
                deltaIn = (s.inBytes >= prev.inBytes)
                    ? (s.inBytes - prev.inBytes)
                    : s.inBytes;
            }

            prev.outBytes = s.outBytes;
            prev.inBytes = s.inBytes;
            prev.valid = true;
            m_previousBytes.insert(key, prev);

            sqlite3_bind_text(stmt, 1, today.toUtf8().constData(),
                              -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(stmt, 2, s.process.toUtf8().constData(),
                              -1, SQLITE_TRANSIENT);
            sqlite3_bind_int64(stmt, 3, deltaOut);
            sqlite3_bind_int64(stmt, 4, deltaIn);
            sqlite3_step(stmt);
            sqlite3_reset(stmt);
        }
        sqlite3_finalize(stmt);
    }

    sqlite3_exec(db, "COMMIT;", nullptr, nullptr, nullptr);
}

// ============================================================
// Queries
// ============================================================

QVector<BwSample> HistoryDB::getLastHour(const QString &process)
{
    QMutexLocker lock(&m_mutex);
    QVector<BwSample> r;

    if (!m_open)
        return r;

    qint64 since = QDateTime::currentSecsSinceEpoch() - 3600;
    const char *sql =
        "SELECT ts, pid, process, out_bps, in_bps, out_bytes, in_bytes"
        " FROM bw_samples"
        " WHERE process = ? AND ts >= ?"
        " ORDER BY ts ASC;";

    sqlite3 *db = reinterpret_cast<sqlite3 *>(m_db);
    sqlite3_stmt *stmt = nullptr;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK || !stmt)
        return r;

    sqlite3_bind_text(stmt, 1, process.toUtf8().constData(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 2, since);

    while (sqlite3_step(stmt) == SQLITE_ROW)
    {
        BwSample s;
        s.ts = sqlite3_column_int64(stmt, 0);
        s.pid = sqlite3_column_int(stmt, 1);
        s.process = QString::fromUtf8(reinterpret_cast<const char *>(
            sqlite3_column_text(stmt, 2)));
        s.outBps = quint32(sqlite3_column_int64(stmt, 3));
        s.inBps = quint32(sqlite3_column_int64(stmt, 4));
        s.outBytes = quint64(sqlite3_column_int64(stmt, 5));
        s.inBytes = quint64(sqlite3_column_int64(stmt, 6));
        r.append(s);
    }
    sqlite3_finalize(stmt);
    return r;
}

QVector<BwSample> HistoryDB::getLast24h(const QString &process)
{
    QMutexLocker lock(&m_mutex);
    QVector<BwSample> r;

    if (!m_open)
        return r;

    qint64 since = QDateTime::currentSecsSinceEpoch() - 86400;

    // Bucket into 1-hour averages for a clean 24-point chart
    const char *sql =
        "SELECT (ts / 3600) * 3600 AS hour, process,"
        "       AVG(out_bps), AVG(in_bps),"
        "       SUM(out_bytes), SUM(in_bytes)"
        " FROM bw_samples"
        " WHERE process = ? AND ts >= ?"
        " GROUP BY hour"
        " ORDER BY hour ASC;";

    sqlite3 *db = reinterpret_cast<sqlite3 *>(m_db);
    sqlite3_stmt *stmt = nullptr;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK || !stmt)
        return r;

    sqlite3_bind_text(stmt, 1, process.toUtf8().constData(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 2, since);

    while (sqlite3_step(stmt) == SQLITE_ROW)
    {
        BwSample s;
        s.ts = sqlite3_column_int64(stmt, 0);
        s.process = QString::fromUtf8(reinterpret_cast<const char *>(
            sqlite3_column_text(stmt, 1)));
        s.outBps = quint32(sqlite3_column_double(stmt, 2));
        s.inBps = quint32(sqlite3_column_double(stmt, 3));
        s.outBytes = quint64(sqlite3_column_int64(stmt, 4));
        s.inBytes = quint64(sqlite3_column_int64(stmt, 5));
        r.append(s);
    }
    sqlite3_finalize(stmt);
    return r;
}

QVector<DailyTotal> HistoryDB::getDailyTotals(const QString &process, int days)
{
    QMutexLocker lock(&m_mutex);
    QVector<DailyTotal> r;

    if (!m_open)
        return r;

    QString since =
        QDate::currentDate().addDays(-days).toString("yyyy-MM-dd");
    const char *sql =
        "SELECT date, process, total_out, total_in"
        " FROM daily_totals"
        " WHERE process = ? AND date >= ?"
        " ORDER BY date ASC;";

    sqlite3 *db = reinterpret_cast<sqlite3 *>(m_db);
    sqlite3_stmt *stmt = nullptr;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK || !stmt)
        return r;

    sqlite3_bind_text(stmt, 1, process.toUtf8().constData(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, since.toUtf8().constData(), -1, SQLITE_TRANSIENT);

    while (sqlite3_step(stmt) == SQLITE_ROW)
    {
        DailyTotal d;
        d.date = QString::fromUtf8(reinterpret_cast<const char *>(
            sqlite3_column_text(stmt, 0)));
        d.process = QString::fromUtf8(reinterpret_cast<const char *>(
            sqlite3_column_text(stmt, 1)));
        d.totalOut = quint64(sqlite3_column_int64(stmt, 2));
        d.totalIn = quint64(sqlite3_column_int64(stmt, 3));
        r.append(d);
    }
    sqlite3_finalize(stmt);
    return r;
}

QVector<DailyTotal> HistoryDB::getAllDailyTotals(int days)
{
    QMutexLocker lock(&m_mutex);
    QVector<DailyTotal> r;

    if (!m_open)
        return r;

    QString since =
        QDate::currentDate().addDays(-days).toString("yyyy-MM-dd");
    const char *sql =
        "SELECT date, 'ALL' AS process,"
        "       SUM(total_out), SUM(total_in)"
        " FROM daily_totals"
        " WHERE date >= ?"
        " GROUP BY date"
        " ORDER BY date ASC;";

    sqlite3 *db = reinterpret_cast<sqlite3 *>(m_db);
    sqlite3_stmt *stmt = nullptr;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK || !stmt)
        return r;

    sqlite3_bind_text(stmt, 1, since.toUtf8().constData(), -1, SQLITE_TRANSIENT);

    while (sqlite3_step(stmt) == SQLITE_ROW)
    {
        DailyTotal d;
        d.date = QString::fromUtf8(reinterpret_cast<const char *>(
            sqlite3_column_text(stmt, 0)));
        d.process = "*";
        d.totalOut = quint64(sqlite3_column_int64(stmt, 2));
        d.totalIn = quint64(sqlite3_column_int64(stmt, 3));
        r.append(d);
    }
    sqlite3_finalize(stmt);
    return r;
}

QStringList HistoryDB::getProcessList()
{
    QMutexLocker lock(&m_mutex);
    QStringList r;

    if (!m_open)
        return r;

    const char *sql =
        "SELECT DISTINCT process FROM bw_samples ORDER BY process ASC;";

    sqlite3 *db = reinterpret_cast<sqlite3 *>(m_db);
    sqlite3_stmt *stmt = nullptr;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK || !stmt)
        return r;

    while (sqlite3_step(stmt) == SQLITE_ROW)
        r << QString::fromUtf8(reinterpret_cast<const char *>(
            sqlite3_column_text(stmt, 0)));

    sqlite3_finalize(stmt);
    return r;
}
