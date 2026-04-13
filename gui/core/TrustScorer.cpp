#include "TrustScorer.h"
#include "ProcEntry.h"
#include "TrafficEntry.h"
#include <QMutexLocker>

TrustScorer &TrustScorer::instance()
{
    static TrustScorer inst;
    return inst;
}

TrustScore TrustScorer::score(const ProcEntry &proc,
                              const QVector<TrafficEntry> &conns) const
{
    TrustScore ts;
    ts.process = proc.process;
    ts.score = 100;
    ts.reasons.clear();

    // Deduct for anomalies
    if (proc.hasAnomaly())
    {
        ts.score -= 40;
        ts.reasons.append(proc.anomalyStr);
    }

    // Deduct for unknown exe
    if (proc.exe.isEmpty() || proc.exe == "unknown")
    {
        ts.score -= 20;
        ts.reasons.append("unknown exe");
    }

    // Deduct for /tmp or /dev/shm paths (suspicious)
    if (proc.exe.startsWith("/tmp") || proc.exe.startsWith("/dev/shm") || proc.exe.startsWith("/run/user"))
    {
        ts.score -= 30;
        ts.reasons.append("suspicious path");
    }

    // Deduct for very high connection count
    if (proc.totalConns > 100)
    {
        ts.score -= 15;
        ts.reasons.append("high conn count");
    }
    else if (proc.totalConns > 50)
    {
        ts.score -= 5;
    }

    // Deduct for very high bandwidth
    quint32 totalRate = proc.rateOutBps + proc.rateInBps;
    if (totalRate > 10 * 1024 * 1024)
    { // >10 MB/s
        ts.score -= 10;
        ts.reasons.append("very high BW");
    }

    // Known trusted system processes
    static const QStringList trusted = {
        "systemd", "systemd-resolve", "NetworkManager",
        "sshd", "dbus-daemon", "avahi-daemon",
        "chronyd", "rsyslogd", "journald"};
    for (const QString &t : trusted)
    {
        if (proc.process.startsWith(t))
        {
            ts.score = qMax(ts.score, 75);
            break;
        }
    }

    ts.score = qBound(0, ts.score, 100);

    // Grade
    if (ts.score >= 90)
    {
        ts.grade = "A";
        ts.color = QColor("#20d060");
    }
    else if (ts.score >= 75)
    {
        ts.grade = "B";
        ts.color = QColor("#3fb950");
    }
    else if (ts.score >= 60)
    {
        ts.grade = "C";
        ts.color = QColor("#f0b800");
    }
    else if (ts.score >= 40)
    {
        ts.grade = "D";
        ts.color = QColor("#f07000");
    }
    else
    {
        ts.grade = "F";
        ts.color = QColor("#f04040");
    }

    return ts;
}

TrustLevel TrustScorer::getLevel(const QString &process) const
{
    QMutexLocker locker(&m_entriesMutex);
    return m_entries.value(process, TrustEntry{process}).level;
}

void TrustScorer::setLevel(const QString &process,
                           TrustLevel level,
                           const QString &reason)
{
    QMutexLocker locker(&m_entriesMutex);
    TrustEntry e;
    e.process = process;
    e.level = level;
    e.reason = reason;
    e.manual = true;
    switch (level)
    {
    case TrustLevel::Trusted:
        e.score = 90;
        break;
    case TrustLevel::Neutral:
        e.score = 50;
        break;
    case TrustLevel::Suspicious:
        e.score = 20;
        break;
    case TrustLevel::Blocked:
        e.score = 0;
        break;
    default:
        e.score = 50;
        break;
    }
    m_entries[process] = e;
    emit trustChanged(process);
}

TrustEntry TrustScorer::getEntry(const QString &process) const
{
    QMutexLocker locker(&m_entriesMutex);
    return m_entries.value(process, TrustEntry{process});
}

QList<TrustEntry> TrustScorer::allEntries() const
{
    QMutexLocker locker(&m_entriesMutex);
    return m_entries.values();
}

QString TrustScorer::labelForLevel(TrustLevel l)
{
    switch (l)
    {
    case TrustLevel::Trusted:
        return "Trusted";
    case TrustLevel::Neutral:
        return "Neutral";
    case TrustLevel::Suspicious:
        return "Suspicious";
    case TrustLevel::Blocked:
        return "Blocked";
    default:
        return "Unknown";
    }
}
