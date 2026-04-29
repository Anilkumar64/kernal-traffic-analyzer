#pragma once
#include <QString>

struct DnsEntry {
    QString domain;
    QString ip;
    int     ttlRemaining = 0;
    int     queriedByPid = 0;
    QString queriedByComm;
    qint64  firstSeen = 0;
    qint64  lastSeen = 0;
    int     queryCount = 1;

    QString ttlString() const {
        if (ttlRemaining <= 0) return "expired";
        if (ttlRemaining < 60) return QString("%1s").arg(ttlRemaining);
        return QString("%1m%2s").arg(ttlRemaining/60).arg(ttlRemaining%60);
    }
};
