#pragma once
#include <QVector>
#include <QMap>
#include "TrafficEntry.h"
#include "ProcEntry.h"
#include "RouteEntry.h"
#include "DnsEntry.h"
#include "AnomalyEntry.h"

struct ProcSnapshot {
    QVector<TrafficEntry>    connections;
    QVector<ProcEntry>       processes;
    QVector<DnsEntry>        dnsMap;
    QVector<AnomalyEntry>    anomalies;
    QMap<QString,RouteEntry> routes;

    int anomalyCount() const { return anomalies.size(); }
};

class ProcReader {
public:
    static ProcSnapshot              readAll();
    static QVector<TrafficEntry>     readConnections();
    static QVector<ProcEntry>        readProcesses();
    static QVector<DnsEntry>         readDnsMap();
    static QVector<AnomalyEntry>     readAnomalies();
    static QMap<QString,RouteEntry>  readRoutes();

    // Preserve rate history across refreshes
    // Key: "srcIp:srcPort-destIp:destPort"
    static QMap<QString, RateHistory> s_histOut;
    static QMap<QString, RateHistory> s_histIn;

private:
    static ConnState parseState(const QString &s);
    static QString   connKey(const TrafficEntry &e);
};
