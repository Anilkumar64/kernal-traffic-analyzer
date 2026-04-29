/**
 * @file ProcReader.h
 * @brief Threaded reader for Kernel Traffic Analyzer proc files.
 * @details Defines all GUI record structures and a QObject that refreshes proc data from a worker thread so the Qt event loop remains responsive.
 * @author Kernel Traffic Analyzer Project
 * @license MIT
 */
#pragma once

#include <QObject>
#include <QThread>
#include <QVector>
#include <QString>
#include <QStringList>

/**
 * @brief One network connection row from /proc/traffic_analyzer.
 */
struct ConnectionRecord {
    int pid{0};
    QString process;
    QString exe;
    QString state;
    QString proto;
    QString srcIp;
    QString dstIp;
    QString domain;
    int srcPort{0};
    int dstPort{0};
    bool resolved{false};
    bool dnsResolved{false};
    quint64 bytesIn{0};
    quint64 bytesOut{0};
    quint64 pktsIn{0};
    quint64 pktsOut{0};
    quint64 rateIn{0};
    quint64 rateOut{0};
    QString firstSeen;
    QString lastSeen;
    int anomalyFlags{0};
};

/**
 * @brief One process aggregate row from /proc/traffic_analyzer_procs.
 */
struct ProcRecord {
    int pid{0};
    QString process;
    int connections{0};
    int tcpCount{0};
    int udpCount{0};
    quint64 totalIn{0};
    quint64 totalOut{0};
    quint64 rateIn{0};
    quint64 rateOut{0};
    int anomalyFlags{0};
    int newConnsSec{0};
    int uniqueDstPorts{0};
};

/**
 * @brief One DNS cache row from /proc/traffic_analyzer_dns.
 */
struct DnsRecord {
    QString ip;
    QString domain;
    QString firstSeen;
    QString lastSeen;
    int queryCount{0};
};

/**
 * @brief One anomaly row from /proc/traffic_analyzer_anomaly.
 */
struct AnomalyRecord {
    int pid{0};
    QString process;
    QString flagNames;
    QString severity;
    QString firstSeen;
    int anomalyFlags{0};
};

/**
 * @brief One traceroute hop row from /proc/traffic_analyzer_routes.
 */
struct RouteRecord {
    QString targetIp;
    QString domain;
    QString hopIp;
    QString country;
    QString lat;
    QString lon;
    QString asn;
    QString org;
    int hopNum{0};
    double rttMs{0.0};
};

/**
 * @brief Global kernel module counters from /proc/traffic_analyzer_stats.
 */
struct GlobalStats {
    quint64 totalPackets{0};
    quint64 totalBytes{0};
    quint64 activeConns{0};
    quint64 activeProcs{0};
    quint64 dnsEntries{0};
    quint64 uptimeSec{0};
};

/**
 * @brief Complete data snapshot emitted by ProcReader.
 */
struct ParsedData {
    QVector<ConnectionRecord> connections;
    QVector<ProcRecord> processes;
    QVector<DnsRecord> dns;
    QVector<AnomalyRecord> anomalies;
    QVector<RouteRecord> routes;
    GlobalStats stats;
    bool moduleLoaded{false};
};

Q_DECLARE_METATYPE(ParsedData)

/**
 * @brief Reads all KTA proc files on a dedicated worker thread.
 */
class ProcReader : public QObject {
    Q_OBJECT

public:
    /**
     * @brief Constructs the reader and starts its worker thread.
     * @param parent Optional QObject parent; leave null when moving to the worker thread.
     */
    explicit ProcReader(QObject* parent = nullptr);

    /**
     * @brief Stops the worker thread and releases resources.
     */
    ~ProcReader() override;

    /**
     * @brief Queues a refresh on the worker thread.
     */
    void requestRefresh();

signals:
    /**
     * @brief Emitted when a full snapshot is available.
     * @param data Parsed kernel traffic data.
     */
    void dataReady(const ParsedData& data);

    /**
     * @brief Emitted when the primary proc file is not present.
     */
    void moduleNotLoaded();

private slots:
    /**
     * @brief Worker-thread slot that reads and emits a snapshot.
     */
    void doRead();

private:
    /**
     * @brief Reads every proc source into one snapshot.
     * @return ParsedData containing all table data.
     */
    ParsedData readAll();

    /** @brief Parses connection records. @return Connection vector. */
    QVector<ConnectionRecord> parseConnections();
    /** @brief Parses process records. @return Process vector. */
    QVector<ProcRecord> parseProcesses();
    /** @brief Parses DNS records. @return DNS vector. */
    QVector<DnsRecord> parseDns();
    /** @brief Parses anomaly records. @return Anomaly vector. */
    QVector<AnomalyRecord> parseAnomalies();
    /** @brief Parses route hop records. @return Route vector. */
    QVector<RouteRecord> parseRoutes();
    /** @brief Parses global stats. @return Global stats. */
    GlobalStats parseStats();

    /**
     * @brief Reads a proc file and skips the first header line.
     * @param path Absolute proc path.
     * @return Non-empty data lines, or an empty list on failure.
     */
    QStringList readProcFile(const QString& path);

    QThread* worker_thread_{nullptr};
};
