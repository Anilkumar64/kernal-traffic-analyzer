#pragma once
#include <QObject>
#include <QMap>
#include <QString>

struct ThrottleRule {
    QString process;
    int     pid       = 0;
    quint32 limitKbps = 0;
};

class BandwidthThrottler : public QObject
{
    Q_OBJECT
public:
    static BandwidthThrottler &instance();
    static bool isAvailable();
    bool    setLimit(const QString &process, int pid, quint32 limitKbps);
    bool    removeLimit(const QString &process);
    void    removeAll();
    bool    isThrottled(const QString &process) const;
    quint32 getLimit(const QString &process) const;
signals:
    void throttleChanged();
private:
    BandwidthThrottler() = default;
    QMap<QString, ThrottleRule> m_rules;
};
