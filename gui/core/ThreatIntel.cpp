#include "ThreatIntel.h"
#include <QHostAddress>
#include <QDateTime>
#include <QMutexLocker>

const QStringList ThreatIntel::s_knownBadPrefixes = {
    "185.220.",
    "185.107.",
    "185.130.",
    "194.165.",
    "194.147.",
    "45.142.",
    "45.153.",
    "45.155.",
    "198.54.",
    "198.98.",
    "5.188.",
    "5.182.",
    "23.129.",
    "204.8.156.",
    "199.87.154.",
};
const QStringList ThreatIntel::s_torExitPrefixes = {
    "23.129.",
    "199.87.",
    "204.8.",
    "185.220.",
    "66.220.",
};

ThreatIntel &ThreatIntel::instance()
{
    static ThreatIntel inst;
    return inst;
}
void ThreatIntel::checkIp(const QString &ip)
{
    QMutexLocker locker(&m_cacheMutex);
    if (m_cache.contains(ip) && m_cache[ip].checked)
        return;
    QHostAddress addr(ip);
    if (addr.isLoopback() || addr.isLinkLocal())
        return;
    if (!addr.toIPv4Address())
        return;
    ThreatInfo info;
    info.ip = ip;
    info.checked = true;
    info.lastSeen = QDateTime::currentSecsSinceEpoch();
    info.level = heuristicLevel(ip);
    info.category = heuristicCategory(ip);
    switch (info.level)
    {
    case ThreatLevel::Clean:
        info.score = 0;
        break;
    case ThreatLevel::Low:
        info.score = 20;
        break;
    case ThreatLevel::Medium:
        info.score = 50;
        break;
    case ThreatLevel::High:
        info.score = 75;
        break;
    case ThreatLevel::Critical:
        info.score = 95;
        break;
    }
    m_cache[ip] = info;
    if (info.level >= ThreatLevel::Medium)
        emit threatDetected(info);
}
ThreatInfo ThreatIntel::getInfo(const QString &ip) const
{
    QMutexLocker locker(&m_cacheMutex);
    return m_cache.value(ip, ThreatInfo{ip, ThreatLevel::Clean, 0, "", 0, false});
}
ThreatLevel ThreatIntel::heuristicLevel(const QString &ip) const
{
    for (const QString &p : s_torExitPrefixes)
        if (ip.startsWith(p))
            return ThreatLevel::High;
    for (const QString &p : s_knownBadPrefixes)
        if (ip.startsWith(p))
            return ThreatLevel::Medium;
    return ThreatLevel::Clean;
}
QString ThreatIntel::heuristicCategory(const QString &ip) const
{
    for (const QString &p : s_torExitPrefixes)
        if (ip.startsWith(p))
            return "Tor Exit Node";
    for (const QString &p : s_knownBadPrefixes)
        if (ip.startsWith(p))
            return "Suspicious Range";
    return "Clean";
}
QColor ThreatIntel::colorForLevel(ThreatLevel level)
{
    switch (level)
    {
    case ThreatLevel::Clean:
        return QColor("#20d060");
    case ThreatLevel::Low:
        return QColor("#30c0f0");
    case ThreatLevel::Medium:
        return QColor("#f0b800");
    case ThreatLevel::High:
        return QColor("#f04040");
    case ThreatLevel::Critical:
        return QColor("#ff00ff");
    }
    return QColor("#6e8399");
}
QString ThreatIntel::labelForLevel(ThreatLevel level)
{
    switch (level)
    {
    case ThreatLevel::Clean:
        return "Clean";
    case ThreatLevel::Low:
        return "Low";
    case ThreatLevel::Medium:
        return "Medium";
    case ThreatLevel::High:
        return "High";
    case ThreatLevel::Critical:
        return "Critical";
    }
    return "Unknown";
}
