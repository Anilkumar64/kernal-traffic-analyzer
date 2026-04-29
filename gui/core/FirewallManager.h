#pragma once
#include <QObject>
#include <QVector>
#include <QSet>
#include <QString>

struct FirewallRule {
    QString id;
    QString destIp;
    int     destPort = 0;
    QString protocol;
    QString comment;
};

class FirewallManager : public QObject
{
    Q_OBJECT
public:
    static FirewallManager &instance();
    static bool isAvailable();
    bool blockIp(const QString &ip, const QString &comment = {});
    bool unblock(const QString &ruleId);
    void unblockAll();
    bool isBlocked(const QString &ip) const;
    QVector<FirewallRule> rules() const { return m_rules; }
signals:
    void rulesChanged();
    void unblockFailed(const QString &ip, const QString &error);
private:
    FirewallManager() = default;
    bool runIptables(const QStringList &args, QString *error = nullptr);
    QVector<FirewallRule> m_rules;
    QSet<QString>         m_blockedIps;
};
