#pragma once
#include <QObject>
#include <QVector>
#include <QMap>
#include <QTimer>
#include "RouteEntry.h"

struct RouteFingerprint {
    QVector<int>     asns;
    QVector<QString> countries;
    int              count = 0;
};

struct DomainFingerprints {
    QString              domain;
    qint64               firstSeen = 0;
    QVector<RouteFingerprint> prints;
};

struct BgpAlert {
    qint64   timestamp = 0;
    QString  domain;
    QString  ip;
    QStringList expectedCountries;
    QStringList actualCountries;
    QString  risk;
};

class BgpMonitor : public QObject
{
    Q_OBJECT
public:
    explicit BgpMonitor(QObject *parent = nullptr);
    void start();
    void stop();
    void updateRoute(const QString &ip,
                     const QString &domain,
                     const RouteEntry &route);
    QVector<BgpAlert> alerts() const { return m_alerts; }
    QMap<QString, DomainFingerprints> learnedRoutes() const { return m_learned; }
    bool isLearning() const;
    int  learningDaysComplete() const;

signals:
    void bgpAlertDetected(BgpAlert alert);
    void dataChanged();

private:
    void loadFromDisk();
    void saveToDisk();
    QString storagePath() const;

    RouteFingerprint buildFingerprint(const RouteEntry &route) const;
    bool fingerprinthMatch(const RouteFingerprint &a,
                           const RouteFingerprint &b) const;
    double countrySimilarity(const QVector<QString> &a,
                             const QVector<QString> &b) const;

    QMap<QString, DomainFingerprints> m_learned;
    QVector<BgpAlert> m_alerts;
    QTimer *m_saveTimer = nullptr;
    qint64  m_startTime = 0;
    static constexpr int LEARNING_DAYS = 7;
};
