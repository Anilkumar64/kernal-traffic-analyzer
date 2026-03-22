#pragma once
#include <QObject>
#include <QMap>
#include <QString>
#include <QColor>

enum class ThreatLevel { Clean=0, Low=1, Medium=2, High=3, Critical=4 };

struct ThreatInfo {
    QString     ip;
    ThreatLevel level    = ThreatLevel::Clean;
    int         score    = 0;
    QString     category;
    qint64      lastSeen = 0;
    bool        checked  = false;
};

class ThreatIntel : public QObject
{
    Q_OBJECT
public:
    static ThreatIntel &instance();
    void       checkIp(const QString &ip);
    ThreatInfo getInfo(const QString &ip) const;
    static QColor  colorForLevel(ThreatLevel level);
    static QString labelForLevel(ThreatLevel level);
signals:
    void threatDetected(const ThreatInfo &info);
private:
    ThreatIntel() = default;
    ThreatLevel heuristicLevel(const QString &ip) const;
    QString     heuristicCategory(const QString &ip) const;
    QMap<QString, ThreatInfo> m_cache;
    static const QStringList s_knownBadPrefixes;
    static const QStringList s_torExitPrefixes;
};
