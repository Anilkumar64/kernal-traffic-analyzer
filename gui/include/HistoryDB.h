/**
 * @file HistoryDB.h
 * @brief SQLite snapshot history store.
 * @details Manages GUI session rows, periodic traffic snapshots, range queries, deletion, and 30-day pruning using Qt SQL.
 * @author Kernel Traffic Analyzer Project
 * @license MIT
 */
#pragma once

#include "ProcReader.h"

#include <QDateTime>
#include <QSqlDatabase>
#include <QVector>

/**
 * @brief Metadata for a stored snapshot row.
 */
struct SnapshotMeta {
    int id{0};
    int sessionId{0};
    QDateTime timestamp;
};

/**
 * @brief SQLite-backed history database for KTA snapshots.
 */
class HistoryDB {
public:
    /** @brief Opens the database, creates schema, and starts a session. @param path SQLite file path. @return True on success. */
    bool open(const QString& path);
    /** @brief Saves a JSON snapshot of connections and processes. @param data Current parsed data. */
    void saveSnapshot(const ParsedData& data);
    /** @brief Queries snapshot metadata in a time range. @param from Start time. @param to End time. @return Matching snapshots. */
    QVector<SnapshotMeta> queryRange(const QDateTime& from, const QDateTime& to);
    /** @brief Returns a full snapshot JSON document. @param id Snapshot ID. @return JSON text. */
    QString getSnapshotJson(int id);
    /** @brief Deletes one snapshot. @param id Snapshot ID. */
    void deleteSnapshot(int id);
    /** @brief Marks the current session end time. */
    void endSession();
    /** @brief Removes snapshots older than 30 days. */
    void pruneOld();

private:
    /** @brief Creates schema objects. @return True on success. */
    bool createSchema();
    /** @brief Starts a new session row. @return True on success. */
    bool startSession();
    /** @brief Encodes connection records as JSON text. @param records Records. @return JSON string. */
    QString connectionsJson(const QVector<ConnectionRecord>& records) const;
    /** @brief Encodes process records as JSON text. @param records Records. @return JSON string. */
    QString procsJson(const QVector<ProcRecord>& records) const;

    QSqlDatabase db_;
    QString connection_name_;
    int current_session_id_{-1};
};
