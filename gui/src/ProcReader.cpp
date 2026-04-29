/**
 * @file ProcReader.cpp
 * @brief Implementation of threaded proc-file reading.
 * @details Performs all /proc I/O on ProcReader's worker thread and converts pipe-delimited kernel rows into strongly typed GUI records.
 * @author Kernel Traffic Analyzer Project
 * @license MIT
 */
#include "ProcReader.h"

#include <QFile>
#include <QFileInfo>
#include <QMetaObject>
#include <QTextStream>

namespace {
/**
 * @brief Converts a field to integer with fallback.
 * @param value Text field.
 * @return Parsed integer or zero.
 */
int toIntSafe(const QString& value)
{
    bool ok = false;
    const int parsed = value.trimmed().toInt(&ok);
    return ok ? parsed : 0;
}

/**
 * @brief Converts a field to unsigned integer with fallback.
 * @param value Text field.
 * @return Parsed unsigned integer or zero.
 */
quint64 toU64Safe(const QString& value)
{
    bool ok = false;
    const quint64 parsed = value.trimmed().toULongLong(&ok);
    return ok ? parsed : 0;
}

/**
 * @brief Converts a field to double with fallback.
 * @param value Text field.
 * @return Parsed double or zero.
 */
double toDoubleSafe(const QString& value)
{
    bool ok = false;
    const double parsed = value.trimmed().toDouble(&ok);
    return ok ? parsed : 0.0;
}

/**
 * @brief Converts kernel truthy text to bool.
 * @param value Text field.
 * @return True for 1, true, yes, or resolved.
 */
bool toBoolSafe(const QString& value)
{
    const QString normalized = value.trimmed().toUpper();
    return normalized == "1" || normalized == "TRUE" || normalized == "YES" || normalized == "RESOLVED";
}
}

ProcReader::ProcReader(QObject* parent)
    : QObject(parent)
{
    qRegisterMetaType<ParsedData>("ParsedData");
}

ProcReader::~ProcReader()
{
}

void ProcReader::requestRefresh()
{
    doRead();
}

void ProcReader::doRead()
{
    const ParsedData data = readAll();
    if (!data.moduleLoaded) {
        emit moduleNotLoaded();
    }
    emit dataReady(data);
}

ParsedData ProcReader::readAll()
{
    ParsedData data;
    data.moduleLoaded = QFileInfo::exists("/proc/traffic_analyzer");
    if (!data.moduleLoaded) {
        return data;
    }
    data.connections = parseConnections();
    data.processes = parseProcesses();
    data.dns = parseDns();
    data.anomalies = parseAnomalies();
    data.routes = parseRoutes();
    data.stats = parseStats();
    return data;
}

QVector<ConnectionRecord> ProcReader::parseConnections()
{
    QVector<ConnectionRecord> records;
    const QStringList lines = readProcFile("/proc/traffic_analyzer");
    records.reserve(lines.size());
    for (const QString& line : lines) {
        const QStringList t = line.split('|');
        if (t.size() < 22) {
            continue;
        }
        ConnectionRecord r;
        r.pid = toIntSafe(t.at(0));
        r.process = t.at(2).trimmed();
        r.exe = t.at(3).trimmed();
        r.resolved = toBoolSafe(t.at(4));
        r.state = t.at(5).trimmed();
        r.dnsResolved = toBoolSafe(t.at(6));
        r.proto = t.at(7).trimmed();
        r.srcIp = t.at(8).trimmed();
        r.srcPort = toIntSafe(t.at(9));
        r.dstIp = t.at(10).trimmed();
        r.dstPort = toIntSafe(t.at(11));
        r.domain = t.at(12).trimmed();
        r.bytesIn = toU64Safe(t.at(13));
        r.bytesOut = toU64Safe(t.at(14));
        r.pktsIn = toU64Safe(t.at(15));
        r.pktsOut = toU64Safe(t.at(16));
        r.rateIn = toU64Safe(t.at(17));
        r.rateOut = toU64Safe(t.at(18));
        r.firstSeen = t.at(19).trimmed();
        r.lastSeen = t.at(20).trimmed();
        r.anomalyFlags = toIntSafe(t.at(21));
        records.append(r);
    }
    return records;
}

QVector<ProcRecord> ProcReader::parseProcesses()
{
    QVector<ProcRecord> records;
    const QStringList lines = readProcFile("/proc/traffic_analyzer_procs");
    records.reserve(lines.size());
    for (const QString& line : lines) {
        const QStringList t = line.split('|');
        if (t.size() < 13) {
            continue;
        }
        ProcRecord r;
        r.pid = toIntSafe(t.at(0));
        r.process = t.at(2).trimmed();
        r.connections = toIntSafe(t.at(3));
        r.tcpCount = toIntSafe(t.at(4));
        r.udpCount = toIntSafe(t.at(5));
        r.totalIn = toU64Safe(t.at(6));
        r.totalOut = toU64Safe(t.at(7));
        r.rateIn = toU64Safe(t.at(8));
        r.rateOut = toU64Safe(t.at(9));
        r.anomalyFlags = toIntSafe(t.at(10));
        r.newConnsSec = toIntSafe(t.at(11));
        r.uniqueDstPorts = toIntSafe(t.at(12));
        records.append(r);
    }
    return records;
}

QVector<DnsRecord> ProcReader::parseDns()
{
    QVector<DnsRecord> records;
    const QStringList lines = readProcFile("/proc/traffic_analyzer_dns");
    records.reserve(lines.size());
    for (const QString& line : lines) {
        const QStringList t = line.split('|');
        if (t.size() < 5) {
            continue;
        }
        DnsRecord r;
        r.ip = t.at(0).trimmed();
        r.domain = t.at(1).trimmed();
        r.firstSeen = t.at(2).trimmed();
        r.lastSeen = t.at(3).trimmed();
        r.queryCount = toIntSafe(t.at(4));
        records.append(r);
    }
    return records;
}

QVector<AnomalyRecord> ProcReader::parseAnomalies()
{
    QVector<AnomalyRecord> records;
    const QStringList lines = readProcFile("/proc/traffic_analyzer_anomaly");
    records.reserve(lines.size());
    for (const QString& line : lines) {
        const QStringList t = line.split('|');
        if (t.size() < 6) {
            continue;
        }
        AnomalyRecord r;
        r.pid = toIntSafe(t.at(0));
        r.process = t.at(1).trimmed();
        r.anomalyFlags = toIntSafe(t.at(2));
        r.flagNames = t.at(3).trimmed();
        r.severity = t.at(4).trimmed();
        r.firstSeen = t.at(5).trimmed();
        records.append(r);
    }
    return records;
}

QVector<RouteRecord> ProcReader::parseRoutes()
{
    QVector<RouteRecord> records;
    const QStringList lines = readProcFile("/proc/traffic_analyzer_routes");
    records.reserve(lines.size());
    for (const QString& line : lines) {
        const QStringList t = line.split('|');
        if (t.size() < 9) {
            continue;
        }
        RouteRecord r;
        r.targetIp = t.at(0).trimmed();
        r.hopNum = toIntSafe(t.at(1));
        r.hopIp = t.at(2).trimmed();
        r.rttMs = toDoubleSafe(t.at(3));
        r.country = t.at(4).trimmed();
        r.lat = t.at(5).trimmed();
        r.lon = t.at(6).trimmed();
        r.asn = t.at(7).trimmed();
        r.org = t.at(8).trimmed();
        records.append(r);
    }
    return records;
}

GlobalStats ProcReader::parseStats()
{
    GlobalStats stats;
    const QStringList lines = readProcFile("/proc/traffic_analyzer_stats");
    for (const QString& line : lines) {
        const QStringList t = line.split('|');
        if (t.size() < 2) {
            continue;
        }
        const QString key = t.at(0).trimmed().toUpper();
        const quint64 value = toU64Safe(t.at(1));
        if (key == "TOTAL_PACKETS") {
            stats.totalPackets = value;
        } else if (key == "TOTAL_BYTES") {
            stats.totalBytes = value;
        } else if (key == "ACTIVE_CONNECTIONS") {
            stats.activeConns = value;
        } else if (key == "ACTIVE_PROCESSES") {
            stats.activeProcs = value;
        } else if (key == "DNS_ENTRIES") {
            stats.dnsEntries = value;
        } else if (key == "MODULE_UPTIME_SEC") {
            stats.uptimeSec = value;
        }
    }
    return stats;
}

QStringList ProcReader::readProcFile(const QString& path)
{
    QFile file(path);
    if (!file.open(QIODevice::ReadOnly | QIODevice::Text)) {
        return {};
    }

    QStringList lines;
    QTextStream stream(&file);
    bool first = true;
    while (!stream.atEnd()) {
        const QString line = stream.readLine().trimmed();
        if (first) {
            first = false;
            continue;
        }
        if (!line.isEmpty()) {
            lines.append(line);
        }
    }
    return lines;
}
