#pragma once
#include <QObject>
#include <QString>
#include "ProcReader.h"

class Exporter : public QObject
{
    Q_OBJECT
public:
    explicit Exporter(QObject *parent = nullptr);
    [[nodiscard]] bool exportJson(const QString &path, const ProcSnapshot &snap);
    [[nodiscard]] bool exportCsv(const QString &path, const QVector<TrafficEntry> &conns);
};
