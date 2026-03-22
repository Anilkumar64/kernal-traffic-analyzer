#include "FirewallManager.h"
#include <QProcess>
#include <QUuid>

FirewallManager &FirewallManager::instance()
{
    static FirewallManager inst;
    return inst;
}
bool FirewallManager::isAvailable()
{
    QProcess p;
    p.start("iptables", {"-L", "-n"});
    p.waitForFinished(2000);
    return p.exitCode() == 0;
}
bool FirewallManager::runIptables(const QStringList &args)
{
    QProcess p;
    p.start("iptables", args);
    p.waitForFinished(5000);
    return p.exitCode() == 0;
}
bool FirewallManager::blockIp(const QString &ip, const QString &comment)
{
    if (m_blockedIps.contains(ip)) return true;
    QStringList args = {"-I","OUTPUT","-d",ip,"-j","DROP",
                        "-m","comment","--comment",
                        comment.isEmpty() ? "kta-block" : comment};
    if (!runIptables(args)) return false;
    FirewallRule rule;
    rule.id      = QUuid::createUuid().toString(QUuid::WithoutBraces);
    rule.destIp  = ip;
    rule.comment = comment;
    m_rules.prepend(rule);
    m_blockedIps.insert(ip);
    emit rulesChanged();
    return true;
}
bool FirewallManager::unblock(const QString &ruleId)
{
    for (int i = 0; i < m_rules.size(); ++i) {
        if (m_rules[i].id == ruleId) {
            const FirewallRule &r = m_rules[i];
            runIptables({"-D","OUTPUT","-d",r.destIp,"-j","DROP",
                         "-m","comment","--comment",
                         r.comment.isEmpty() ? "kta-block" : r.comment});
            m_blockedIps.remove(r.destIp);
            m_rules.removeAt(i);
            emit rulesChanged();
            return true;
        }
    }
    return false;
}
void FirewallManager::unblockAll()
{
    for (const auto &r : m_rules)
        runIptables({"-D","OUTPUT","-d",r.destIp,"-j","DROP",
                     "-m","comment","--comment",
                     r.comment.isEmpty() ? "kta-block" : r.comment});
    m_rules.clear();
    m_blockedIps.clear();
    emit rulesChanged();
}
bool FirewallManager::isBlocked(const QString &ip) const
{
    return m_blockedIps.contains(ip);
}
