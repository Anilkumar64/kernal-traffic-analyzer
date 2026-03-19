#pragma once
#include <QString>

enum class ConnState {
    SynSent, SynRecv, Established, FinWait, Closed, UdpActive, Unknown
};

struct TrafficEntry {
    int       pid = 0;
    int       uid = 0;
    QString   process;
    bool      resolved = false;
    ConnState state = ConnState::Unknown;
    bool      isDns = false;
    QString   protocol;
    QString   srcIp;
    QString   destIp;
    int       srcPort = 0;
    int       destPort = 0;
    QString   domain;
    qint64    bytesOut = 0;
    qint64    bytesIn = 0;
    qint64    pktsOut = 0;
    qint64    pktsIn = 0;
    quint32   rateOutBps = 0;
    quint32   rateInBps = 0;
    qint64    firstSeen = 0;
    qint64    lastSeen = 0;
    qint64    duration = 0;
    qint64    closedAt = 0;

    bool isActive() const {
        return state == ConnState::Established || state == ConnState::UdpActive;
    }
    bool isClosed() const { return state == ConnState::Closed; }

    QString stateString() const {
        switch (state) {
        case ConnState::SynSent:     return "SYN_SENT";
        case ConnState::SynRecv:     return "SYN_RECV";
        case ConnState::Established: return "ESTABLISHED";
        case ConnState::FinWait:     return "FIN_WAIT";
        case ConnState::Closed:      return "CLOSED";
        case ConnState::UdpActive:   return "UDP_ACTIVE";
        default:                     return "UNKNOWN";
        }
    }

    QString durationString() const {
        if (duration < 60)   return QString("%1s").arg(duration);
        if (duration < 3600) return QString("%1m%2s").arg(duration/60).arg(duration%60);
        return QString("%1h%2m").arg(duration/3600).arg((duration%3600)/60);
    }

    QString formatBytes(qint64 b) const {
        if (b < 1024)        return QString("%1 B").arg(b);
        if (b < 1048576)     return QString("%1 KB").arg(b/1024.0, 0, 'f', 1);
        if (b < 1073741824)  return QString("%1 MB").arg(b/1048576.0, 0, 'f', 1);
        return               QString("%1 GB").arg(b/1073741824.0, 0, 'f', 2);
    }

    QString formatRate(quint32 bps) const {
        if (bps == 0)        return "-";
        if (bps < 1024)      return QString("%1 B/s").arg(bps);
        if (bps < 1048576)   return QString("%1 KB/s").arg(bps/1024.0, 0, 'f', 1);
        return               QString("%1 MB/s").arg(bps/1048576.0, 0, 'f', 1);
    }
};
