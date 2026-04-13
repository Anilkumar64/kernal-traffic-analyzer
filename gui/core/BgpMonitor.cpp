#include "BgpMonitor.h"
#include <QStandardPaths>
#include <QDir>
#include <QFile>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>
#include <QDateTime>

BgpMonitor::BgpMonitor(QObject *parent) : QObject(parent)
{
    m_startTime = QDateTime::currentSecsSinceEpoch();
    m_saveTimer = new QTimer(this);
    m_saveTimer->setInterval(60000); // save every minute
    connect(m_saveTimer, &QTimer::timeout, this, &BgpMonitor::saveToDisk);
}

void BgpMonitor::start()
{
    loadFromDisk();
    m_saveTimer->start();
}

void BgpMonitor::stop()
{
    m_saveTimer->stop();
    saveToDisk();
}

QString BgpMonitor::storagePath() const
{
    QString dir = QStandardPaths::writableLocation(
        QStandardPaths::AppLocalDataLocation);
    QDir().mkpath(dir);
    return dir + "/route_history.json";
}

bool BgpMonitor::isLearning() const
{
    qint64 elapsed = QDateTime::currentSecsSinceEpoch() - m_startTime;
    return elapsed < LEARNING_DAYS * 86400;
}

int BgpMonitor::learningDaysComplete() const
{
    qint64 elapsed = QDateTime::currentSecsSinceEpoch() - m_startTime;
    return qMin(int(elapsed / 86400), LEARNING_DAYS);
}

RouteFingerprint BgpMonitor::buildFingerprint(const RouteEntry &route) const
{
    RouteFingerprint fp;
    QSet<QString> seenCountry;
    for (const auto &hop : route.hops)
    {
        if (hop.asn > 0)
            fp.asns.append(hop.asn);
        if (!hop.cc.isEmpty() && hop.cc != "-" &&
            !seenCountry.contains(hop.cc))
        {
            seenCountry.insert(hop.cc);
            fp.countries.append(hop.cc);
        }
    }
    fp.count = 1;
    return fp;
}

double BgpMonitor::countrySimilarity(const QVector<QString> &a,
                                     const QVector<QString> &b) const
{
    if (a.isEmpty() || b.isEmpty())
        return 1.0;
    QSet<QString> sa(a.begin(), a.end());
    QSet<QString> sb(b.begin(), b.end());
    QSet<QString> inter = sa & sb;
    QSet<QString> uni = sa | sb;
    return uni.isEmpty() ? 1.0 : double(inter.size()) / double(uni.size());
}

bool BgpMonitor::fingerprinthMatch(const RouteFingerprint &a,
                                   const RouteFingerprint &b) const
{
    return countrySimilarity(a.countries, b.countries) >= 0.7;
}

void BgpMonitor::updateRoute(const QString &ip,
                             const QString &domain,
                             const RouteEntry &route)
{
    if (!route.isReady() || domain.isEmpty() || domain == "-")
        return;

    RouteFingerprint newFp = buildFingerprint(route);
    if (newFp.countries.isEmpty())
        return;

    if (!m_learned.contains(domain))
    {
        DomainFingerprints df;
        df.domain = domain;
        df.firstSeen = QDateTime::currentSecsSinceEpoch();
        df.prints.append(newFp);
        m_learned[domain] = df;
        emit dataChanged();
        return;
    }

    DomainFingerprints &df = m_learned[domain];

    // Check if this fingerprint matches any known one
    for (auto &fp : df.prints)
    {
        if (fingerprinthMatch(fp, newFp))
        {
            fp.count++;
            emit dataChanged();
            return;
        }
    }

    // New fingerprint — check if it's suspicious
    if (!isLearning() && !df.prints.isEmpty())
    {
        // Find most common fingerprint
        const RouteFingerprint &common = *std::max_element(
            df.prints.begin(), df.prints.end(),
            [](const RouteFingerprint &a, const RouteFingerprint &b)
            {
                return a.count < b.count;
            });

        double sim = countrySimilarity(common.countries, newFp.countries);
        if (sim < 0.5)
        {
            BgpAlert alert;
            alert.timestamp = QDateTime::currentSecsSinceEpoch();
            alert.domain = domain;
            alert.ip = ip;
            alert.expectedCountries = QStringList(
                common.countries.begin(), common.countries.end());
            alert.actualCountries = QStringList(
                newFp.countries.begin(), newFp.countries.end());
            alert.risk = sim < 0.2 ? "HIGH" : "MEDIUM";

            m_alerts.prepend(alert);
            if (m_alerts.size() > 100)
                m_alerts.resize(100);

            emit bgpAlertDetected(alert);
        }
    }

    // Add new fingerprint
    df.prints.append(newFp);
    if (df.prints.size() > 20)
        df.prints.removeFirst();
    emit dataChanged();
}

void BgpMonitor::loadFromDisk()
{
    QFile f(storagePath());
    if (!f.open(QIODevice::ReadOnly))
        return;
    QJsonObject root = QJsonDocument::fromJson(f.readAll()).object();

    m_startTime = root.value("start_time").toDouble(QDateTime::currentSecsSinceEpoch());

    QJsonObject domains = root.value("domains").toObject();
    for (auto it = domains.begin(); it != domains.end(); ++it)
    {
        DomainFingerprints df;
        QJsonObject dobj = it.value().toObject();
        df.domain = it.key();
        df.firstSeen = qint64(dobj.value("first_seen").toDouble());

        for (const auto &fpv : dobj.value("fingerprints").toArray())
        {
            QJsonObject fpo = fpv.toObject();
            RouteFingerprint fp;
            for (const auto &a : fpo.value("asns").toArray())
                fp.asns.append(a.toInt());
            for (const auto &c : fpo.value("countries").toArray())
                fp.countries.append(c.toString());
            fp.count = fpo.value("count").toInt(1);
            df.prints.append(fp);
        }
        m_learned[it.key()] = df;
    }
}

void BgpMonitor::saveToDisk()
{
    QJsonObject root;
    root["start_time"] = double(m_startTime);

    QJsonObject domains;
    for (auto it = m_learned.begin(); it != m_learned.end(); ++it)
    {
        const DomainFingerprints &df = it.value();
        QJsonObject dobj;
        dobj["first_seen"] = double(df.firstSeen);

        QJsonArray fps;
        for (const auto &fp : df.prints)
        {
            QJsonObject fpo;
            QJsonArray asns, countries;
            for (int a : fp.asns)
                asns.append(a);
            for (const QString &c : fp.countries)
                countries.append(c);
            fpo["asns"] = asns;
            fpo["countries"] = countries;
            fpo["count"] = fp.count;
            fps.append(fpo);
        }
        dobj["fingerprints"] = fps;
        domains[it.key()] = dobj;
    }
    root["domains"] = domains;

    QFile f(storagePath());
    if (!f.open(QIODevice::WriteOnly))
    {
        qWarning() << "BgpMonitor: failed to save to" << storagePath();
        return;
    }
    if (f.write(QJsonDocument(root).toJson()) == -1)
        qWarning() << "BgpMonitor: write failed to" << storagePath();
}