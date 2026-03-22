#include "BandwidthThrottler.h"
#include <QProcess>

BandwidthThrottler &BandwidthThrottler::instance()
{
    static BandwidthThrottler inst;
    return inst;
}
bool BandwidthThrottler::isAvailable()
{
    QProcess p;
    p.start("which", {"tc"});
    p.waitForFinished(2000);
    return p.exitCode() == 0;
}
bool BandwidthThrottler::setLimit(const QString &process, int pid, quint32 limitKbps)
{
    ThrottleRule r;
    r.process   = process;
    r.pid       = pid;
    r.limitKbps = limitKbps;
    m_rules[process] = r;
    emit throttleChanged();
    return true;
}
bool BandwidthThrottler::removeLimit(const QString &process)
{
    if (!m_rules.contains(process)) return false;
    m_rules.remove(process);
    emit throttleChanged();
    return true;
}
void BandwidthThrottler::removeAll()
{
    m_rules.clear();
    emit throttleChanged();
}
bool BandwidthThrottler::isThrottled(const QString &process) const
{
    return m_rules.contains(process);
}
quint32 BandwidthThrottler::getLimit(const QString &process) const
{
    return m_rules.value(process).limitKbps;
}
