/**
 * @file Exporter.cpp
 * @brief Implementation of JSON and CSV exporting.
 * @details Converts ParsedData into structured JSON or per-table CSV files using Qt JSON and file APIs.
 * @author Kernel Traffic Analyzer Project
 * @license MIT
 */
#include "Exporter.h"

#include <QDateTime>
#include <QDir>
#include <QFile>
#include <QFileDialog>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QMessageBox>
#include <QTextStream>

namespace {
/**
 * @brief Escapes one CSV field.
 * @param value Field value.
 * @return Escaped field.
 */
QString csvEscape(const QString& value)
{
    QString out = value;
    out.replace('"', "\"\"");
    if (out.contains(',') || out.contains('"') || out.contains('\n')) {
        out = QString("\"%1\"").arg(out);
    }
    return out;
}

/**
 * @brief Writes text to a file with an error dialog.
 * @param path Destination path.
 * @param text Text content.
 * @param parent Dialog parent.
 * @return True on success.
 */
bool writeTextFile(const QString& path, const QString& text, QWidget* parent)
{
    QFile file(path);
    if (!file.open(QIODevice::WriteOnly | QIODevice::Text | QIODevice::Truncate)) {
        QMessageBox::warning(parent, "Export Failed", QString("Could not write %1.").arg(path));
        return false;
    }
    QTextStream out(&file);
    out << text;
    return true;
}
}

void Exporter::exportJson(const ParsedData& data, QWidget* parent)
{
    const QString path = QFileDialog::getSaveFileName(parent, "Export JSON", "kta-export.json", "JSON Files (*.json)");
    if (path.isEmpty()) {
        return;
    }

    QJsonObject root;
    QJsonObject metadata;
    metadata["exported_at"] = QDateTime::currentDateTimeUtc().toString(Qt::ISODate);
    metadata["version"] = "1.0.0";
    root["metadata"] = metadata;
    root["connections"] = QJsonDocument::fromJson(connectionsToJson(data.connections).toUtf8()).array();
    root["processes"] = QJsonDocument::fromJson(procsToJson(data.processes).toUtf8()).array();

    QJsonArray dns;
    for (const DnsRecord& r : data.dns) {
        QJsonObject o;
        o["ip"] = r.ip;
        o["domain"] = r.domain;
        o["first_seen"] = r.firstSeen;
        o["last_seen"] = r.lastSeen;
        o["query_count"] = r.queryCount;
        dns.append(o);
    }
    root["dns"] = dns;

    QJsonArray anomalies;
    for (const AnomalyRecord& r : data.anomalies) {
        QJsonObject o;
        o["pid"] = r.pid;
        o["process"] = r.process;
        o["flag_names"] = r.flagNames;
        o["severity"] = r.severity;
        o["first_seen"] = r.firstSeen;
        o["anomaly_flags"] = r.anomalyFlags;
        anomalies.append(o);
    }
    root["anomalies"] = anomalies;

    if (writeTextFile(path, QString::fromUtf8(QJsonDocument(root).toJson(QJsonDocument::Indented)), parent)) {
        QMessageBox::information(parent, "Export Complete", "JSON export completed.");
    }
}

void Exporter::exportCsv(const ParsedData& data, QWidget* parent)
{
    const QString dir = QFileDialog::getExistingDirectory(parent, "Export CSV Directory");
    if (dir.isEmpty()) {
        return;
    }
    const QDir outDir(dir);
    const bool ok = writeTextFile(outDir.filePath("connections.csv"), connectionsToCsv(data.connections), parent)
        && writeTextFile(outDir.filePath("processes.csv"), procsToCsv(data.processes), parent)
        && writeTextFile(outDir.filePath("dns.csv"), dnsToCsv(data.dns), parent)
        && writeTextFile(outDir.filePath("anomalies.csv"), anomaliesToCsv(data.anomalies), parent);
    if (ok) {
        QMessageBox::information(parent, "Export Complete", "CSV export completed.");
    }
}

QString Exporter::connectionsToJson(const QVector<ConnectionRecord>& recs)
{
    QJsonArray array;
    for (const ConnectionRecord& r : recs) {
        QJsonObject o;
        o["pid"] = r.pid;
        o["process"] = r.process;
        o["exe"] = r.exe;
        o["resolved"] = r.resolved;
        o["state"] = r.state;
        o["dns"] = r.dnsResolved;
        o["proto"] = r.proto;
        o["src_ip"] = r.srcIp;
        o["src_port"] = r.srcPort;
        o["dst_ip"] = r.dstIp;
        o["dst_port"] = r.dstPort;
        o["domain"] = r.domain;
        o["bytes_in"] = QString::number(r.bytesIn);
        o["bytes_out"] = QString::number(r.bytesOut);
        o["pkts_in"] = QString::number(r.pktsIn);
        o["pkts_out"] = QString::number(r.pktsOut);
        o["rate_in"] = QString::number(r.rateIn);
        o["rate_out"] = QString::number(r.rateOut);
        o["first_seen"] = r.firstSeen;
        o["last_seen"] = r.lastSeen;
        o["anomaly_flags"] = r.anomalyFlags;
        array.append(o);
    }
    return QString::fromUtf8(QJsonDocument(array).toJson(QJsonDocument::Compact));
}

QString Exporter::procsToJson(const QVector<ProcRecord>& recs)
{
    QJsonArray array;
    for (const ProcRecord& r : recs) {
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

QString Exporter::connectionsToCsv(const QVector<ConnectionRecord>& recs)
{
    QString out = "PID,Process,Exe,Resolved,State,DNS,Proto,Src IP,Src Port,Dst IP,Dst Port,Domain,Bytes In,Bytes Out,Pkts In,Pkts Out,Rate In,Rate Out,First Seen,Last Seen,Anomaly Flags\n";
    for (const ConnectionRecord& r : recs) {
        QStringList row = {QString::number(r.pid), r.process, r.exe, r.resolved ? "1" : "0", r.state, r.dnsResolved ? "1" : "0", r.proto, r.srcIp, QString::number(r.srcPort), r.dstIp, QString::number(r.dstPort), r.domain, QString::number(r.bytesIn), QString::number(r.bytesOut), QString::number(r.pktsIn), QString::number(r.pktsOut), QString::number(r.rateIn), QString::number(r.rateOut), r.firstSeen, r.lastSeen, QString::number(r.anomalyFlags)};
        for (QString& field : row) {
            field = csvEscape(field);
        }
        out += row.join(',') + '\n';
    }
    return out;
}

QString Exporter::procsToCsv(const QVector<ProcRecord>& recs)
{
    QString out = "PID,Process,Connections,TCP Count,UDP Count,Total In,Total Out,Rate In,Rate Out,Anomaly Flags,New Conns/Sec,Unique Dst Ports\n";
    for (const ProcRecord& r : recs) {
        QStringList row = {QString::number(r.pid), r.process, QString::number(r.connections), QString::number(r.tcpCount), QString::number(r.udpCount), QString::number(r.totalIn), QString::number(r.totalOut), QString::number(r.rateIn), QString::number(r.rateOut), QString::number(r.anomalyFlags), QString::number(r.newConnsSec), QString::number(r.uniqueDstPorts)};
        for (QString& field : row) {
            field = csvEscape(field);
        }
        out += row.join(',') + '\n';
    }
    return out;
}

QString Exporter::dnsToCsv(const QVector<DnsRecord>& recs)
{
    QString out = "IP,Domain,First Seen,Last Seen,Query Count\n";
    for (const DnsRecord& r : recs) {
        QStringList row = {r.ip, r.domain, r.firstSeen, r.lastSeen, QString::number(r.queryCount)};
        for (QString& field : row) {
            field = csvEscape(field);
        }
        out += row.join(',') + '\n';
    }
    return out;
}

QString Exporter::anomaliesToCsv(const QVector<AnomalyRecord>& recs)
{
    QString out = "PID,Process,Anomaly Flags,Flag Names,Severity,First Seen\n";
    for (const AnomalyRecord& r : recs) {
        QStringList row = {QString::number(r.pid), r.process, QString::number(r.anomalyFlags), r.flagNames, r.severity, r.firstSeen};
        for (QString& field : row) {
            field = csvEscape(field);
        }
        out += row.join(',') + '\n';
    }
    return out;
}
