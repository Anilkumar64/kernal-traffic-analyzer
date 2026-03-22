#pragma once
#include <QObject>
#include <QSet>
#include <QVector>
#include <QTimer>
#include <QThread>

enum class LeakSeverity { Info, Warning, Critical };

struct DnsLeakEvent {
    qint64        timestamp  = 0;
    int           pid        = 0;
    QString       process;
    QString       destIp;
    int           destPort   = 53;
    QString       domain;
    LeakSeverity  severity   = LeakSeverity::Info;
    QString       reason;

    QString severityStr() const {
        switch (severity) {
        case LeakSeverity::Info:     return "INFO";
        case LeakSeverity::Warning:  return "WARNING";
        case LeakSeverity::Critical: return "CRITICAL";
        }
        return "INFO";
    }
};

class DnsLeakDetector : public QObject
{
    Q_OBJECT
public:
    explicit DnsLeakDetector(QObject *parent = nullptr);
    void start();
    void stop();
    QVector<DnsLeakEvent> events() const { return m_events; }
    void clearEvents();
    QStringList authorizedResolvers() const;

signals:
    void leakDetected(DnsLeakEvent event);
    void eventsChanged();

private slots:
    void check();

private:
    void loadAuthorizedResolvers();
    void parseResolvConf(const QString &path);

    QTimer  *m_timer = nullptr;
    QSet<QString> m_authorized;
    QVector<DnsLeakEvent> m_events;
    QSet<QString> m_seen; // deduplicate
};
