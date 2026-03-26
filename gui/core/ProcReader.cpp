#include "ProcReader.h"
#include <QFile>
#include <QTextStream>

static QStringList splitLine(const QString &line) { return line.split('|'); }
static void skipHeader(QTextStream &in) { QString l; in.readLineInto(&l); }

ConnState ProcReader::parseState(const QString &s)
{
    if (s == "SYN_SENT")    return ConnState::SynSent;
    if (s == "SYN_RECV")    return ConnState::SynRecv;
    if (s == "ESTABLISHED") return ConnState::Established;
    if (s == "FIN_WAIT")    return ConnState::FinWait;
    if (s == "CLOSED")      return ConnState::Closed;
    if (s == "UDP_ACTIVE")  return ConnState::UdpActive;
    return ConnState::Unknown;
}

QMap<QString, RateHistory> ProcReader::s_histOut;
QMap<QString, RateHistory> ProcReader::s_histIn;

QString ProcReader::connKey(const TrafficEntry &e) {
    return QString("%1:%2-%3:%4")
        .arg(e.srcIp).arg(e.srcPort)
        .arg(e.destIp).arg(e.destPort);
}

QVector<TrafficEntry> ProcReader::readConnections()
{
    QVector<TrafficEntry> r;
    QFile f("/proc/traffic_analyzer");
    if (!f.open(QIODevice::ReadOnly | QIODevice::Text)) return r;
    QTextStream in(&f);
    skipHeader(in);
    while (!in.atEnd()) {
        QString line = in.readLine().trimmed();
        if (line.isEmpty() || line.startsWith('#')) continue;
        QStringList t = splitLine(line);
        if (t.size() < 22) continue;
        TrafficEntry e;
        e.pid        = t[0].toInt();
        e.uid        = t[1].toInt();
        e.process    = t[2];
        e.resolved   = (t[3] == "YES");
        e.state      = parseState(t[4]);
        e.isDns      = (t[5] == "YES");
        e.protocol   = t[6];
        e.srcIp      = t[8];   // local IP (NAT)
        e.destIp     = t[7];   // real remote IP
        e.srcPort    = t[10].toInt();
        e.destPort   = t[9].toInt();
        e.domain     = t[11];
        e.bytesOut   = t[12].toLongLong();
        e.bytesIn    = t[13].toLongLong();
        e.pktsOut    = t[14].toLongLong();
        e.pktsIn     = t[15].toLongLong();
        e.rateOutBps = t[16].toUInt();
        e.rateInBps  = t[17].toUInt();
        e.firstSeen  = t[18].toLongLong();
        e.lastSeen   = t[19].toLongLong();
        e.duration   = t[20].toLongLong();
        e.closedAt   = t[21].toLongLong();

        // Push current rates into history ring buffer
        QString key = connKey(e);
        s_histOut[key].push(e.rateOutBps);
        s_histIn[key].push(e.rateInBps);
        e.histOut = s_histOut[key];
        e.histIn  = s_histIn[key];

        r.append(e);
    }
    return r;
}

QVector<ProcEntry> ProcReader::readProcesses()
{
    QVector<ProcEntry> r;
    QFile f("/proc/traffic_analyzer_procs");
    if (!f.open(QIODevice::ReadOnly | QIODevice::Text)) return r;
    QTextStream in(&f);
    skipHeader(in);
    while (!in.atEnd()) {
        QString line = in.readLine().trimmed();
        if (line.isEmpty() || line.startsWith('#')) continue;
        QStringList t = splitLine(line);
        if (t.size() < 17) continue;
        ProcEntry e;
        e.pid        = t[0].toInt();
        e.uid        = t[1].toInt();
        e.process    = t[2];
        e.exe        = t[3];
        e.tcpConns   = t[4].toInt();
        e.udpConns   = t[5].toInt();
        e.totalConns = t[6].toInt();
        e.synPending = t[7].toInt();
        e.bytesOut   = t[8].toLongLong();
        e.bytesIn    = t[9].toLongLong();
        e.pktsOut    = t[10].toLongLong();
        e.pktsIn     = t[11].toLongLong();
        e.rateOutBps = t[12].toUInt();
        e.rateInBps  = t[13].toUInt();
        e.tcpPct     = t[14].toInt();
        e.udpPct     = t[15].toInt();
        e.anomalyStr = t[16];
        e.anomaly    = ProcEntry::parseAnomaly(t[16]);
        for (int i = 17; i < qMin(t.size(), 22); ++i)
            if (t[i] != "-" && !t[i].isEmpty())
                e.topConns.append(TopConn::parse(t[i]));
        r.append(e);
    }
    return r;
}

QVector<DnsEntry> ProcReader::readDnsMap()
{
    QVector<DnsEntry> r;
    QFile f("/proc/traffic_analyzer_dns_map");
    if (!f.open(QIODevice::ReadOnly | QIODevice::Text)) return r;
    QTextStream in(&f);
    skipHeader(in);
    while (!in.atEnd()) {
        QString line = in.readLine().trimmed();
        if (line.isEmpty() || line.startsWith('#')) continue;
        QStringList t = splitLine(line);
        if (t.size() < 7) continue;
        DnsEntry e;
        e.domain        = t[0];
        e.ip            = t[1];
        e.ttlRemaining  = t[2].toInt();
        e.queriedByPid  = t[3].toInt();
        e.queriedByComm = t[4];
        e.firstSeen     = t[5].toLongLong();
        e.lastSeen      = t[6].toLongLong();
        r.append(e);
    }
    return r;
}

QVector<AnomalyEntry> ProcReader::readAnomalies()
{
    QVector<AnomalyEntry> r;
    QFile f("/proc/traffic_analyzer_anomalies");
    if (!f.open(QIODevice::ReadOnly | QIODevice::Text)) return r;
    QTextStream in(&f);
    skipHeader(in);
    while (!in.atEnd()) {
        QString line = in.readLine().trimmed();
        if (line.isEmpty() || line.startsWith('#')) continue;
        QStringList t = splitLine(line);
        if (t.size() < 11) continue;
        AnomalyEntry e;
        e.pid                = t[0].toInt();
        e.uid                = t[1].toInt();
        e.process            = t[2];
        e.exe                = t[3];
        e.anomaly            = t[4];
        e.newConnsLastSec    = t[5].toInt();
        e.uniquePortsLastSec = t[6].toInt();
        e.totalConns         = t[7].toInt();
        e.synPending         = t[8].toInt();
        e.rateOutBps         = t[9].toUInt();
        e.rateInBps          = t[10].toUInt();
        r.append(e);
    }
    return r;
}

QMap<QString, RouteEntry> ProcReader::readRoutes()
{
    QMap<QString, RouteEntry> r;
    QFile f("/proc/traffic_analyzer_routes");
    if (!f.open(QIODevice::ReadOnly | QIODevice::Text)) return r;
    QTextStream in(&f);
    skipHeader(in);
    while (!in.atEnd()) {
        QString line = in.readLine().trimmed();
        if (line.isEmpty() || line.startsWith('#')) continue;
        QStringList t = splitLine(line);
        if (t.size() < 15) continue;
        QString ip = t[0];
        if (!r.contains(ip)) {
            RouteEntry re;
            re.destIp    = ip;
            re.domain    = t[1];
            re.status    = RouteEntry::parseStatus(t[2]);
            re.totalHops = t[3].toInt();
            r.insert(ip, re);
        }
        RouteHop hop;
        hop.hopN    = t[4].toInt();
        hop.hopIp   = t[5];
        hop.host    = t[6];
        hop.rttMs   = t[7].toDouble();
        hop.city    = t[8];
        hop.country = t[9];
        hop.cc      = t[10];
        hop.lat     = t[11].toLongLong() / 1000000.0;
        hop.lon     = t[12].toLongLong() / 1000000.0;
        hop.asn     = t[13].toInt();
        hop.org     = t[14];
        r[ip].hops.append(hop);
    }
    return r;
}

ProcSnapshot ProcReader::readAll()
{
    ProcSnapshot s;
    s.connections = readConnections();
    s.processes   = readProcesses();
    s.dnsMap      = readDnsMap();
    s.anomalies   = readAnomalies();
    s.routes      = readRoutes();
    return s;
}
