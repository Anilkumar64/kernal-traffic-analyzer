#pragma once
#include <QString>
#include <QVector>
#include "../ui/Style.h"

enum class RouteStatus { Pending, Running, Done, Failed, Unknown };

struct RouteHop {
    int     hopN = 0;
    QString hopIp;
    QString host;
    double  rttMs = 0.0;
    QString city;
    QString country;
    QString cc;
    double  lat = 0.0;
    double  lon = 0.0;
    QString asn;
    QString org;

    bool hasGeo() const { return lat != 0.0 || lon != 0.0; }

    QString rttColorHex() const {
        if (rttMs <= 0)  return Style::css(KtaColors::Text3);
        if (rttMs < 50)  return Style::css(KtaColors::Teal);
        if (rttMs < 150) return Style::css(KtaColors::Amber);
        return Style::css(KtaColors::Red);
    }
};

struct RouteEntry {
    QString     destIp;
    QString     domain;
    RouteStatus status = RouteStatus::Unknown;
    int         totalHops = 0;
    qint64      lastTraced = 0;
    QVector<RouteHop> hops;

    bool isReady() const {
        // Accept Done or Stale — stale means previously traced, still valid
        return (status == RouteStatus::Done ||
                status == RouteStatus::Running) && !hops.isEmpty();
    }

    static RouteStatus parseStatus(const QString &s) {
        if (s == "PENDING") return RouteStatus::Pending;
        if (s == "RUNNING") return RouteStatus::Running;
        if (s == "DONE")    return RouteStatus::Done;
        if (s == "STALE")   return RouteStatus::Done;   // treat stale as done
        if (s == "FAILED")  return RouteStatus::Failed;
        return RouteStatus::Unknown;
    }
};
