#pragma once
#include <QString>
#include <QVector>

enum class AnomalyType { None, ConnBurst, PortScan, HighConns, SynFlood, HighBw, Multi };

struct TopConn {
    QString display;
    QString domain;
    QString proto;
    int     port = 0;
    qint64  bytes = 0;

    static TopConn parse(const QString &raw) {
        TopConn tc;
        tc.display = raw;
        if (raw == "-" || raw.isEmpty()) return tc;
        int sp = raw.indexOf('/');
        if (sp < 0) return tc;
        int sb = raw.indexOf('/', sp + 1);
        if (sb < 0) return tc;
        QString hp = raw.left(sp);
        tc.proto = raw.mid(sp + 1, sb - sp - 1);
        tc.bytes = raw.mid(sb + 1).toLongLong();
        int cp = hp.lastIndexOf(':');
        if (cp >= 0) { tc.domain = hp.left(cp); tc.port = hp.mid(cp+1).toInt(); }
        else tc.domain = hp;
        return tc;
    }
};

struct ProcEntry {
    int     pid = 0;
    int     uid = 0;
    QString process;
    QString exe;
    int     tcpConns = 0;
    int     udpConns = 0;
    int     totalConns = 0;
    int     synPending = 0;
    qint64  bytesOut = 0;
    qint64  bytesIn = 0;
    qint64  pktsOut = 0;
    qint64  pktsIn = 0;
    quint32 rateOutBps = 0;
    quint32 rateInBps = 0;
    int     tcpPct = 0;
    int     udpPct = 0;
    AnomalyType anomaly = AnomalyType::None;
    QString anomalyStr;
    QVector<TopConn> topConns;

    bool hasAnomaly() const { return anomaly != AnomalyType::None; }

    QString exeShort() const {
        if (exe.isEmpty() || exe == "unknown") return process;
        int s = exe.lastIndexOf('/');
        return s >= 0 ? exe.mid(s + 1) : exe;
    }
    QString formatRate(quint32 bps) const {
        if (bps == 0)      return "-";
        if (bps < 1024)    return QString("%1 B/s").arg(bps);
        if (bps < 1048576) return QString("%1 KB/s").arg(bps/1024.0, 0, 'f', 1);
        return             QString("%1 MB/s").arg(bps/1048576.0, 0, 'f', 1);
    }
    QString formatBytes(qint64 b) const {
        if (b < 1024)       return QString("%1 B").arg(b);
        if (b < 1048576)    return QString("%1 KB").arg(b/1024.0, 0, 'f', 1);
        if (b < 1073741824) return QString("%1 MB").arg(b/1048576.0, 0, 'f', 1);
        return              QString("%1 GB").arg(b/1073741824.0, 0, 'f', 2);
    }
    static AnomalyType parseAnomaly(const QString &s) {
        if (s == "NONE")       return AnomalyType::None;
        if (s == "PORT_SCAN")  return AnomalyType::PortScan;
        if (s == "SYN_FLOOD")  return AnomalyType::SynFlood;
        if (s == "CONN_BURST") return AnomalyType::ConnBurst;
        if (s == "HIGH_CONNS") return AnomalyType::HighConns;
        if (s == "HIGH_BW")    return AnomalyType::HighBw;
        if (s == "MULTI")      return AnomalyType::Multi;
        return AnomalyType::None;
    }
};
