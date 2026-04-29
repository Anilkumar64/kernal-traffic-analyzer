#include "Exporter.h"
#include <QDateTime>
#include <QFile>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QTextStream>

Exporter::Exporter(QObject *parent) : QObject(parent) {}

bool Exporter::exportJson(const QString &path, const ProcSnapshot &snap)
{
    QJsonObject root;
    root["generated"] = QDateTime::currentDateTime().toString(Qt::ISODate);
    root["version"] = "1.0";

    QJsonArray connections;
    for (const auto &e : snap.connections) {
        QJsonObject o;
        o["pid"] = e.pid;
        o["process"] = e.process;
        o["protocol"] = e.protocol;
        o["local"] = QString("%1:%2").arg(e.srcIp).arg(e.srcPort);
        o["remote"] = QString("%1:%2").arg(e.destIp).arg(e.destPort);
        o["domain"] = e.domain;
        o["state"] = e.stateString();
        o["bytes_in"] = double(e.bytesIn);
        o["bytes_out"] = double(e.bytesOut);
        o["rate_in_bps"] = int(e.rateInBps);
        o["rate_out_bps"] = int(e.rateOutBps);
        connections.append(o);
    }
    root["connections"] = connections;

    QJsonArray processes;
    for (const auto &p : snap.processes) {
        QJsonObject o;
        o["pid"] = p.pid;
        o["process"] = p.process;
        o["exe"] = p.exe;
        o["connections"] = p.totalConns;
        o["bytes_in"] = double(p.bytesIn);
        o["bytes_out"] = double(p.bytesOut);
        o["rate_in_bps"] = int(p.rateInBps);
        o["rate_out_bps"] = int(p.rateOutBps);
        processes.append(o);
    }
    root["processes"] = processes;

    QFile file(path);
    if (!file.open(QIODevice::WriteOnly))
        return false;
    file.write(QJsonDocument(root).toJson(QJsonDocument::Indented));
    return true;
}

bool Exporter::exportCsv(const QString &path, const QVector<TrafficEntry> &conns)
{
    QFile file(path);
    if (!file.open(QIODevice::WriteOnly | QIODevice::Text))
        return false;

    QTextStream out(&file);
    out << "PID,PROCESS,PROTOCOL,LOCAL,REMOTE,DOMAIN,STATE,IN_BYTES,OUT_BYTES,IN_RATE_BPS,OUT_RATE_BPS\n";
    for (const auto &e : conns) {
        out << e.pid << ',' << '"' << e.process << '"' << ',' << e.protocol << ','
            << e.srcIp << ':' << e.srcPort << ',' << e.destIp << ':' << e.destPort << ','
            << '"' << e.domain << '"' << ',' << e.stateString() << ','
            << e.bytesIn << ',' << e.bytesOut << ',' << e.rateInBps << ',' << e.rateOutBps << '\n';
    }
    return true;
}
