#pragma once
#include <QString>

struct AnomalyEntry {
    int     pid = 0;
    int     uid = 0;
    QString process;
    QString exe;
    QString anomaly;
    int     newConnsLastSec = 0;
    int     uniquePortsLastSec = 0;
    int     totalConns = 0;
    int     synPending = 0;
    quint32 rateOutBps = 0;
    quint32 rateInBps = 0;

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
};
