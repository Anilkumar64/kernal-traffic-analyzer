#include "DnsLeakDetector.h"
#include <QFile>
#include <QTextStream>
#include <QDateTime>
#include <QRegularExpression>

DnsLeakDetector::DnsLeakDetector(QObject *parent) : QObject(parent)
{
    m_timer = new QTimer(this);
    m_timer->setInterval(5000);
    connect(m_timer, &QTimer::timeout, this, &DnsLeakDetector::check);
}

void DnsLeakDetector::start()
{
    loadAuthorizedResolvers();
    m_timer->start();
}

void DnsLeakDetector::stop()
{
    m_timer->stop();
}

void DnsLeakDetector::clearEvents()
{
    m_events.clear();
    m_seen.clear();
    emit eventsChanged();
}

QStringList DnsLeakDetector::authorizedResolvers() const
{
    return QStringList(m_authorized.begin(), m_authorized.end());
}

void DnsLeakDetector::parseResolvConf(const QString &path)
{
    QFile f(path);
    if (!f.open(QIODevice::ReadOnly | QIODevice::Text)) return;
    QTextStream in(&f);
    QRegularExpression re(R"(^nameserver\s+(\S+))");
    while (!in.atEnd()) {
        QString line = in.readLine().trimmed();
        auto m = re.match(line);
        if (m.hasMatch()) m_authorized.insert(m.captured(1));
    }
}

void DnsLeakDetector::loadAuthorizedResolvers()
{
    m_authorized.clear();
    // Always allow loopback
    m_authorized.insert("127.0.0.1");
    m_authorized.insert("127.0.0.53"); // systemd-resolved stub
    m_authorized.insert("::1");

    parseResolvConf("/etc/resolv.conf");
    parseResolvConf("/run/systemd/resolve/resolv.conf");
    parseResolvConf("/run/systemd/resolve/stub-resolv.conf");
}

void DnsLeakDetector::check()
{
    // Re-load resolvers in case they changed
    loadAuthorizedResolvers();

    QFile f("/proc/traffic_analyzer");
    if (!f.open(QIODevice::ReadOnly | QIODevice::Text)) return;

    QTextStream in(&f);
    QString header = in.readLine(); // skip header
    Q_UNUSED(header)

    while (!in.atEnd()) {
        QString line = in.readLine().trimmed();
        if (line.isEmpty()) continue;
        QStringList t = line.split('|');
        if (t.size() < 22) continue;

        int     pid      = t[0].toInt();
        QString process  = t[2];
        QString proto    = t[6];
        QString destIp   = t[8];
        int     destPort = t[10].toInt();
        QString domain   = t[11];

        // Only care about DNS traffic (port 53, UDP/TCP)
        if (destPort != 53) continue;
        if (proto != "UDP" && proto != "TCP") continue;

        // Check if destination is authorized
        bool authorized = m_authorized.contains(destIp);

        if (!authorized) {
            QString key = QString("%1:%2:%3").arg(process).arg(destIp).arg(pid);
            if (m_seen.contains(key)) continue;
            m_seen.insert(key);

            DnsLeakEvent ev;
            ev.timestamp = QDateTime::currentSecsSinceEpoch();
            ev.pid       = pid;
            ev.process   = process;
            ev.destIp    = destIp;
            ev.destPort  = destPort;
            ev.domain    = domain;
            ev.severity  = LeakSeverity::Critical;
            ev.reason    = QString("DNS query to unauthorized resolver %1")
                               .arg(destIp);

            m_events.prepend(ev);
            if (m_events.size() > 200) m_events.resize(200);

            emit leakDetected(ev);
            emit eventsChanged();
        } else if (process != "systemd-reso" &&
                   process != "systemd-resolve" &&
                   !process.startsWith("systemd")) {
            // Non-system process making direct DNS queries — suspicious
            QString key = QString("warn:%1:%2").arg(process).arg(destIp);
            if (m_seen.contains(key)) continue;
            m_seen.insert(key);

            DnsLeakEvent ev;
            ev.timestamp = QDateTime::currentSecsSinceEpoch();
            ev.pid       = pid;
            ev.process   = process;
            ev.destIp    = destIp;
            ev.destPort  = destPort;
            ev.domain    = domain;
            ev.severity  = LeakSeverity::Warning;
            ev.reason    = QString("Process %1 making direct DNS queries")
                               .arg(process);

            m_events.prepend(ev);
            if (m_events.size() > 200) m_events.resize(200);
            emit eventsChanged();
        }
    }
}
