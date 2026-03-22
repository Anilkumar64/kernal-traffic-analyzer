#include "Exporter.h"
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>
#include <QFile>
#include <QTextStream>
#include <QDateTime>
#include <QPrinter>
#include <QPainter>
#include <QPainterPath>
#include <QFont>
#include <QColor>

Exporter::Exporter(QObject *parent) : QObject(parent) {}

// ================================================================
// JSON Export
// ================================================================
bool Exporter::exportJson(const QString &path, const ProcSnapshot &snap)
{
    QJsonObject root;
    root["generated"] = QDateTime::currentDateTime()
                            .toString(Qt::ISODate);
    root["version"]   = "KTA v6.0";

    // Connections
    QJsonArray conns;
    for (const auto &e : snap.connections) {
        QJsonObject o;
        o["pid"]      = e.pid;
        o["process"]  = e.process;
        o["protocol"] = e.protocol;
        o["state"]    = e.stateString();
        o["src"]      = QString("%1:%2").arg(e.srcIp).arg(e.srcPort);
        o["dest"]     = QString("%1:%2").arg(e.destIp).arg(e.destPort);
        o["domain"]   = e.domain;
        o["rate_out"] = int(e.rateOutBps);
        o["rate_in"]  = int(e.rateInBps);
        o["bytes_out"]= double(e.bytesOut);
        o["bytes_in"] = double(e.bytesIn);
        o["duration"] = double(e.duration);
        conns.append(o);
    }
    root["connections"] = conns;

    // Processes
    QJsonArray procs;
    for (const auto &p : snap.processes) {
        QJsonObject o;
        o["pid"]       = p.pid;
        o["process"]   = p.process;
        o["exe"]       = p.exe;
        o["tcp_conns"] = p.tcpConns;
        o["udp_conns"] = p.udpConns;
        o["rate_out"]  = int(p.rateOutBps);
        o["rate_in"]   = int(p.rateInBps);
        o["bytes_out"] = double(p.bytesOut);
        o["bytes_in"]  = double(p.bytesIn);
        o["anomaly"]   = p.anomalyStr;
        procs.append(o);
    }
    root["processes"] = procs;

    // Anomalies
    QJsonArray anomalies;
    for (const auto &a : snap.anomalies) {
        QJsonObject o;
        o["pid"]              = a.pid;
        o["process"]          = a.process;
        o["anomaly"]          = a.anomaly;
        o["new_conns_per_sec"]= a.newConnsLastSec;
        o["unique_ports"]     = a.uniquePortsLastSec;
        anomalies.append(o);
    }
    root["anomalies"] = anomalies;

    // DNS
    QJsonArray dns;
    for (const auto &d : snap.dnsMap) {
        QJsonObject o;
        o["domain"]  = d.domain;
        o["ip"]      = d.ip;
        o["ttl"]     = d.ttlRemaining;
        o["queried_by"] = d.queriedByComm;
        dns.append(o);
    }
    root["dns"] = dns;

    // Cost summary
    auto summary = CostTracker::instance().getMonthlySummary();
    QJsonObject cost;
    cost["used_gb"]    = summary.usedGB;
    cost["cost_inr"]   = summary.costInr;
    cost["limit_gb"]   = summary.limitGB;
    cost["rate_per_gb"]= summary.rateInrPerGb;
    root["cost_summary"] = cost;

    QFile f(path);
    if (!f.open(QIODevice::WriteOnly)) return false;
    f.write(QJsonDocument(root).toJson(QJsonDocument::Indented));
    return true;
}

// ================================================================
// CSV Export
// ================================================================
bool Exporter::exportCsv(const QString &path,
                          const QVector<TrafficEntry> &conns)
{
    QFile f(path);
    if (!f.open(QIODevice::WriteOnly | QIODevice::Text)) return false;
    QTextStream out(&f);

    out << "PID,PROCESS,PROTOCOL,STATE,SRC_IP,SRC_PORT,"
           "DEST_IP,DEST_PORT,DOMAIN,RATE_OUT_BPS,RATE_IN_BPS,"
           "BYTES_OUT,BYTES_IN,DURATION\n";

    for (const auto &e : conns) {
        out << e.pid << ","
            << e.process << ","
            << e.protocol << ","
            << e.stateString() << ","
            << e.srcIp << ","
            << e.srcPort << ","
            << e.destIp << ","
            << e.destPort << ","
            << e.domain << ","
            << e.rateOutBps << ","
            << e.rateInBps << ","
            << e.bytesOut << ","
            << e.bytesIn << ","
            << e.duration << "\n";
    }
    return true;
}

// ================================================================
// PDF Export
// ================================================================
QRect Exporter::pageRect() const
{
    return QRect(MARGIN, MARGIN + 50,
                 595 - MARGIN*2, 842 - MARGIN*2 - 50);
}

void Exporter::drawPageHeader(QPainter &p, const QRect &pr,
                               const QString &title,
                               int pageNum, int totalPages)
{
    Q_UNUSED(pr)
    // Header bar
    p.fillRect(QRect(0, 0, 595, 44), QColor("#0d1117"));

    // KTA hexagon logo
    QPainterPath hex;
    QPointF c(22, 22);
    for (int i = 0; i < 6; ++i) {
        double angle = M_PI/6.0 + i*M_PI/3.0;
        QPointF pt(c.x()+14*qCos(angle), c.y()+14*qSin(angle));
        if (i==0) hex.moveTo(pt); else hex.lineTo(pt);
    }
    hex.closeSubpath();
    p.setPen(QPen(QColor("#1d6ef5"), 1.5));
    p.setBrush(Qt::NoBrush);
    p.drawPath(hex);

    QFont hf("Ubuntu Mono"); hf.setPixelSize(14); hf.setWeight(QFont::Bold);
    p.setFont(hf);
    p.setPen(QColor("#dde8f5"));
    p.drawText(QRect(44, 0, 300, 44), Qt::AlignLeft|Qt::AlignVCenter,
               "KTA  —  " + title);

    QFont sf("Ubuntu Mono"); sf.setPixelSize(10);
    p.setFont(sf);
    p.setPen(QColor("#334455"));
    p.drawText(QRect(400, 0, 180, 44), Qt::AlignRight|Qt::AlignVCenter,
               QString("Page %1 / %2   %3")
                   .arg(pageNum).arg(totalPages)
                   .arg(QDateTime::currentDateTime()
                            .toString("yyyy-MM-dd hh:mm")));

    // Separator
    p.setPen(QPen(QColor("#1c2530"), 1));
    p.drawLine(0, 44, 595, 44);
}

void Exporter::drawTable(QPainter &p, QRect &cursor,
                          const QStringList &headers,
                          const QVector<QStringList> &rows,
                          const QVector<QColor> &rowColors)
{
    int cols = headers.size();
    if (cols == 0) return;
    int colW = (cursor.width()) / cols;
    int rowH = 22;

    // Header
    p.fillRect(QRect(cursor.left(), cursor.top(), cursor.width(), rowH),
               QColor("#131920"));
    QFont hf("Ubuntu Mono"); hf.setPixelSize(9); hf.setWeight(QFont::Bold);
    p.setFont(hf);
    for (int c = 0; c < cols; ++c) {
        p.setPen(QColor("#334455"));
        p.drawText(QRect(cursor.left()+c*colW+4, cursor.top(),
                         colW-4, rowH),
                   Qt::AlignLeft|Qt::AlignVCenter,
                   headers[c]);
    }
    cursor.setTop(cursor.top() + rowH);

    QFont rf("Ubuntu Mono"); rf.setPixelSize(10);
    p.setFont(rf);

    for (int r = 0; r < rows.size(); ++r) {
        QColor bg = (!rowColors.isEmpty() && r < rowColors.size())
                  ? rowColors[r]
                  : (r%2==0 ? QColor("#0d1117") : QColor("#0f1520"));
        p.fillRect(QRect(cursor.left(), cursor.top(), cursor.width(), rowH),
                   bg);
        const QStringList &row = rows[r];
        for (int c = 0; c < qMin(cols, row.size()); ++c) {
            p.setPen(QColor("#dde8f5"));
            p.drawText(QRect(cursor.left()+c*colW+4, cursor.top(),
                             colW-8, rowH),
                       Qt::AlignLeft|Qt::AlignVCenter,
                       row[c]);
        }
        cursor.setTop(cursor.top() + rowH);
    }
    cursor.setTop(cursor.top() + 10);
}

bool Exporter::exportPdf(const QString &path, const ProcSnapshot &snap)
{
    QPrinter printer(QPrinter::HighResolution);
    printer.setOutputFormat(QPrinter::PdfFormat);
    printer.setOutputFileName(path);
    printer.setPageSize(QPageSize(QPageSize::A4));
    printer.setPageMargins(QMarginsF(0,0,0,0));

    QPainter p(&printer);
    if (!p.isActive()) return false;

    // Scale to 595x842 (A4 points)
    double sx = p.device()->width()  / 595.0;
    double sy = p.device()->height() / 842.0;
    p.scale(sx, sy);

    const int TOTAL = 5;

    auto newPage = [&]() {
        printer.newPage();
    };

    // Page 1: Title
    p.fillRect(QRect(0,0,595,842), QColor("#0d1117"));
    drawPageHeader(p, pageRect(), "Network Report", 1, TOTAL);

    QFont titleFont("Ubuntu Mono"); titleFont.setPixelSize(26);
    titleFont.setWeight(QFont::Bold);
    p.setFont(titleFont);
    p.setPen(QColor("#dde8f5"));
    p.drawText(QRect(MARGIN, 200, 595-MARGIN*2, 60),
               Qt::AlignCenter, "Kernel Traffic Analyzer");

    QFont subFont("Ubuntu Mono"); subFont.setPixelSize(14);
    p.setFont(subFont);
    p.setPen(QColor("#6e8399"));
    p.drawText(QRect(MARGIN, 270, 595-MARGIN*2, 30),
               Qt::AlignCenter, "Network Observability Report");

    QFont infoFont("Ubuntu Mono"); infoFont.setPixelSize(12);
    p.setFont(infoFont);
    p.setPen(QColor("#334455"));
    QString ts = QDateTime::currentDateTime()
                     .toString("dddd, MMMM d yyyy  hh:mm:ss");
    p.drawText(QRect(MARGIN, 340, 595-MARGIN*2, 24),
               Qt::AlignCenter, ts);

    // Summary stats
    int active = 0;
    for (const auto &e : snap.connections) if (e.isActive()) active++;
    QStringList stats = {
        QString("Total Connections: %1").arg(snap.connections.size()),
        QString("Active Connections: %1").arg(active),
        QString("Processes Monitored: %1").arg(snap.processes.size()),
        QString("Anomalies Detected: %1").arg(snap.anomalyCount()),
        QString("DNS Entries: %1").arg(snap.dnsMap.size()),
    };
    int sy2 = 400;
    p.setPen(QColor("#5aabff"));
    for (const QString &s : stats) {
        p.drawText(QRect(MARGIN, sy2, 595-MARGIN*2, 22),
                   Qt::AlignCenter, s);
        sy2 += 24;
    }

    // Page 2: Top processes
    newPage();
    p.fillRect(QRect(0,0,595,842), QColor("#0d1117"));
    drawPageHeader(p, pageRect(), "Top Processes by Bandwidth", 2, TOTAL);

    QRect cursor = pageRect();
    QFont secFont("Ubuntu Mono"); secFont.setPixelSize(11);
    secFont.setWeight(QFont::Bold);
    p.setFont(secFont);
    p.setPen(QColor("#334455"));
    p.drawText(cursor.adjusted(0,0,0,-cursor.height()+20),
               Qt::AlignLeft, "BANDWIDTH USAGE BY PROCESS");
    cursor.setTop(cursor.top() + 24);

    auto fmtB = [](quint64 b) -> QString {
        if (b<1024) return QString("%1B").arg(b);
        if (b<1048576) return QString("%1KB").arg(b/1024.0,0,'f',1);
        if (b<1073741824) return QString("%1MB").arg(b/1048576.0,0,'f',1);
        return QString("%1GB").arg(b/1073741824.0,0,'f',2);
    };
    auto fmtR = [](quint32 r2) -> QString {
        if (r2<1024) return QString("%1B/s").arg(r2);
        if (r2<1048576) return QString("%1K/s").arg(r2/1024.0,0,'f',1);
        return QString("%1M/s").arg(r2/1048576.0,0,'f',1);
    };

    QVector<QStringList> procRows;
    int limit = qMin(15, snap.processes.size());
    for (int i = 0; i < limit; ++i) {
        const auto &pr = snap.processes[i];
        procRows.append({
            pr.process,
            QString::number(pr.totalConns),
            fmtR(pr.rateOutBps),
            fmtR(pr.rateInBps),
            fmtB(pr.bytesOut + pr.bytesIn),
            pr.anomalyStr.isEmpty() ? "Clean" : pr.anomalyStr
        });
    }
    drawTable(p, cursor,
              {"PROCESS","CONNS","OUT","IN","TOTAL","ANOMALY"},
              procRows);

    // Page 3: Anomalies
    newPage();
    p.fillRect(QRect(0,0,595,842), QColor("#0d1117"));
    drawPageHeader(p, pageRect(), "Anomalies Detected", 3, TOTAL);
    cursor = pageRect();
    cursor.setTop(cursor.top() + 24);

    if (snap.anomalies.isEmpty()) {
        QFont nf("Ubuntu Mono"); nf.setPixelSize(14);
        p.setFont(nf);
        p.setPen(QColor("#20d060"));
        p.drawText(cursor, Qt::AlignCenter, "No anomalies detected");
    } else {
        QVector<QStringList> aRows;
        QVector<QColor> aColors;
        for (const auto &a : snap.anomalies) {
            aRows.append({
                a.process, a.anomaly,
                QString::number(a.newConnsLastSec),
                QString::number(a.uniquePortsLastSec),
                QString::number(a.totalConns)
            });
            aColors.append(QColor("#1f0808"));
        }
        drawTable(p, cursor,
                  {"PROCESS","ANOMALY","NEW CONNS/s","PORTS","TOTAL"},
                  aRows, aColors);
    }

    // Page 4: Countries / DNS
    newPage();
    p.fillRect(QRect(0,0,595,842), QColor("#0d1117"));
    drawPageHeader(p, pageRect(), "DNS Queries", 4, TOTAL);
    cursor = pageRect();
    cursor.setTop(cursor.top() + 24);

    QVector<QStringList> dnsRows;
    int dnsLimit = qMin(25, snap.dnsMap.size());
    for (int i = 0; i < dnsLimit; ++i) {
        const auto &d = snap.dnsMap[i];
        dnsRows.append({d.domain, d.ip,
                        QString::number(d.ttlRemaining)+"s",
                        d.queriedByComm});
    }
    drawTable(p, cursor,
              {"DOMAIN","IP","TTL","QUERIED BY"},
              dnsRows);

    // Page 5: Cost summary
    newPage();
    p.fillRect(QRect(0,0,595,842), QColor("#0d1117"));
    drawPageHeader(p, pageRect(), "Data Cost Summary", 5, TOTAL);
    cursor = pageRect();
    cursor.setTop(cursor.top() + 24);

    auto summary = CostTracker::instance().getMonthlySummary();
    auto costs   = CostTracker::instance().getProcessCosts(30);

    QFont sf2("Ubuntu Mono"); sf2.setPixelSize(12);
    p.setFont(sf2);
    p.setPen(QColor("#dde8f5"));
    p.drawText(cursor.adjusted(0,0,0,-cursor.height()+22), Qt::AlignLeft,
               QString("ISP Rate: ₹%1 / GB   Monthly Limit: %2 GB")
                   .arg(summary.rateInrPerGb,0,'f',2)
                   .arg(summary.limitGB,0,'f',0));
    cursor.setTop(cursor.top() + 28);
    p.setPen(QColor("#5aabff"));
    p.drawText(cursor.adjusted(0,0,0,-cursor.height()+22), Qt::AlignLeft,
               QString("Used This Month: %1 GB   Cost: ₹%2   Remaining: %3 GB")
                   .arg(summary.usedGB,0,'f',3)
                   .arg(summary.costInr,0,'f',2)
                   .arg(qMax(0.0,summary.limitGB-summary.usedGB),0,'f',2));
    cursor.setTop(cursor.top() + 34);

    QVector<QStringList> costRows;
    for (const auto &c : costs) {
        costRows.append({
            c.process,
            QString("₹%1").arg(c.todayCostInr,0,'f',3),
            QString("₹%1").arg(c.weekCostInr,0,'f',2),
            QString("₹%1").arg(c.totalCostInr,0,'f',2),
            QString("%1%").arg(c.pctOfUsage,0,'f',1)
        });
    }
    drawTable(p, cursor,
              {"PROCESS","TODAY","THIS WEEK","TOTAL","% USAGE"},
              costRows);

    p.end();
    return true;
}
