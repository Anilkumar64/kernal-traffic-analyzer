/**
 * @file HistoryDB.cpp
 * @brief Implementation of the SQLite history store.
 * @details Creates the requested schema, stores snapshots as JSON strings, and exposes range/delete/export helpers.
 * @author Kernel Traffic Analyzer Project
 * @license MIT
 */
#include "HistoryDB.h"

#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QSqlError>
#include <QSqlQuery>
#include <QSqlRecord>
#include <QUuid>

bool HistoryDB::open(const QString& path)
{
    connection_name_ = QString("kta_history_%1").arg(QUuid::createUuid().toString(QUuid::WithoutBraces));
    db_ = QSqlDatabase::addDatabase("QSQLITE", connection_name_);
    db_.setDatabaseName(path);
    if (!db_.open()) {
        return false;
    }
    return createSchema() && startSession();
}

void HistoryDB::saveSnapshot(const ParsedData& data)
{
    if (!db_.isOpen() || current_session_id_ < 0) {
        return;
    }
    QSqlQuery query(db_);
    query.prepare("INSERT INTO snapshots (session_id, timestamp, connections_json, procs_json) VALUES (?, ?, ?, ?)");
    query.addBindValue(current_session_id_);
    query.addBindValue(QDateTime::currentDateTimeUtc().toString(Qt::ISODate));
    query.addBindValue(connectionsJson(data.connections));
    query.addBindValue(procsJson(data.processes));
    query.exec();
}

QVector<SnapshotMeta> HistoryDB::queryRange(const QDateTime& from, const QDateTime& to)
{
    QVector<SnapshotMeta> rows;
    if (!db_.isOpen()) {
        return rows;
    }
    QSqlQuery query(db_);
    query.prepare("SELECT id, session_id, timestamp FROM snapshots WHERE timestamp >= ? AND timestamp <= ? ORDER BY timestamp DESC");
    query.addBindValue(from.toUTC().toString(Qt::ISODate));
    query.addBindValue(to.toUTC().toString(Qt::ISODate));
    if (!query.exec()) {
        return rows;
    }
    while (query.next()) {
        SnapshotMeta meta;
        meta.id = query.value(0).toInt();
        meta.sessionId = query.value(1).toInt();
        meta.timestamp = QDateTime::fromString(query.value(2).toString(), Qt::ISODate);
        rows.append(meta);
    }
    return rows;
}

QString HistoryDB::getSnapshotJson(int id)
{
    if (!db_.isOpen()) {
        return {};
    }
    QSqlQuery query(db_);
    query.prepare("SELECT id, session_id, timestamp, connections_json, procs_json FROM snapshots WHERE id = ?");
    query.addBindValue(id);
    if (!query.exec() || !query.next()) {
        return {};
    }
    QJsonObject root;
    root["id"] = query.value(0).toInt();
    root["session_id"] = query.value(1).toInt();
    root["timestamp"] = query.value(2).toString();
    root["connections"] = QJsonDocument::fromJson(query.value(3).toString().toUtf8()).array();
    root["processes"] = QJsonDocument::fromJson(query.value(4).toString().toUtf8()).array();
    return QString::fromUtf8(QJsonDocument(root).toJson(QJsonDocument::Indented));
}

void HistoryDB::deleteSnapshot(int id)
{
    if (!db_.isOpen()) {
        return;
    }
    QSqlQuery query(db_);
    query.prepare("DELETE FROM snapshots WHERE id = ?");
    query.addBindValue(id);
    query.exec();
}

void HistoryDB::endSession()
{
    if (!db_.isOpen() || current_session_id_ < 0) {
        return;
    }
    QSqlQuery query(db_);
    query.prepare("UPDATE sessions SET end_time = ? WHERE id = ?");
    query.addBindValue(QDateTime::currentDateTimeUtc().toString(Qt::ISODate));
    query.addBindValue(current_session_id_);
    query.exec();
    current_session_id_ = -1;
}

void HistoryDB::pruneOld()
{
    if (!db_.isOpen()) {
        return;
    }
    QSqlQuery query(db_);
    query.prepare("DELETE FROM snapshots WHERE timestamp < ?");
    query.addBindValue(QDateTime::currentDateTimeUtc().addDays(-30).toString(Qt::ISODate));
    query.exec();
}

bool HistoryDB::createSchema()
{
    QSqlQuery query(db_);
    const QStringList statements = {
        "CREATE TABLE IF NOT EXISTS sessions (id INTEGER PRIMARY KEY AUTOINCREMENT, start_time TEXT NOT NULL, end_time TEXT)",
        "CREATE TABLE IF NOT EXISTS snapshots (id INTEGER PRIMARY KEY AUTOINCREMENT, session_id INTEGER NOT NULL REFERENCES sessions(id), timestamp TEXT NOT NULL, connections_json TEXT NOT NULL, procs_json TEXT NOT NULL)",
        "CREATE INDEX IF NOT EXISTS idx_snapshots_time ON snapshots(timestamp)"
    };
    for (const QString& statement : statements) {
        if (!query.exec(statement)) {
            return false;
        }
    }
    return true;
}

bool HistoryDB::startSession()
{
    QSqlQuery query(db_);
    query.prepare("INSERT INTO sessions (start_time) VALUES (?)");
    query.addBindValue(QDateTime::currentDateTimeUtc().toString(Qt::ISODate));
    if (!query.exec()) {
        return false;
    }
    current_session_id_ = query.lastInsertId().toInt();
    return current_session_id_ >= 0;
}

QString HistoryDB::connectionsJson(const QVector<ConnectionRecord>& records) const
{
    QJsonArray array;
    for (const ConnectionRecord& r : records) {
        QJsonObject o;
        o["pid"] = r.pid;
        o["process"] = r.process;
        o["exe"] = r.exe;
        o["state"] = r.state;
        o["proto"] = r.proto;
        o["src_ip"] = r.srcIp;
        o["src_port"] = r.srcPort;
        o["dst_ip"] = r.dstIp;
        o["dst_port"] = r.dstPort;
        o["domain"] = r.domain;
        o["bytes_in"] = QString::number(r.bytesIn);
        o["bytes_out"] = QString::number(r.bytesOut);
        o["rate_in"] = QString::number(r.rateIn);
        o["rate_out"] = QString::number(r.rateOut);
        o["first_seen"] = r.firstSeen;
        o["last_seen"] = r.lastSeen;
        o["anomaly_flags"] = r.anomalyFlags;
        array.append(o);
    }
    return QString::fromUtf8(QJsonDocument(array).toJson(QJsonDocument::Compact));
}

QString HistoryDB::procsJson(const QVector<ProcRecord>& records) const
{
    QJsonArray array;
    for (const ProcRecord& r : records) {
        QJsonObject o;
        o["pid"] = r.pid;
        o["process"] = r.process;
        o["connections"] = r.connections;
        o["tcp_count"] = r.tcpCount;
        o["udp_count"] = r.udpCount;
        o["total_in"] = QString::number(r.totalIn);
        o["total_out"] = QString::number(r.totalOut);
        o["rate_in"] = QString::number(r.rateIn);
        o["rate_out"] = QString::number(r.rateOut);
        o["anomaly_flags"] = r.anomalyFlags;
        o["new_conns_sec"] = r.newConnsSec;
        o["unique_dst_ports"] = r.uniqueDstPorts;
        array.append(o);
    }
    return QString::fromUtf8(QJsonDocument(array).toJson(QJsonDocument::Compact));
}
