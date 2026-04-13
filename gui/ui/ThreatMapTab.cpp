#include <QHostAddress>
#include "ThreatMapTab.h"
#include "Style.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QFrame>
#include <QSplitter>
#include <QHeaderView>
#include <QPainter>
#include <QGraphicsEllipseItem>
#include <QGraphicsLineItem>
#include <QGraphicsTextItem>
#include <QGraphicsPathItem>
#include <QPainterPath>
#include <QDateTime>

ThreatMapTab::ThreatMapTab(QWidget *parent) : QWidget(parent)
{
    auto *outer = new QVBoxLayout(this);
    outer->setContentsMargins(0, 0, 0, 0);
    outer->setSpacing(0);

    // Top bar
    auto *topBar = new QWidget(this);
    topBar->setObjectName("TopBar");
    topBar->setFixedHeight(58);
    auto *tl = new QHBoxLayout(topBar);
    tl->setContentsMargins(20, 0, 20, 0);
    auto *ttl = new QLabel("Network Threat Map", topBar);
    ttl->setStyleSheet("color:#1e2a3a;font-size:15px;font-weight:600;"
                       "font-family:'Ubuntu Mono';");
    m_statusLabel = new QLabel("Scanning connections...", topBar);
    m_statusLabel->setStyleSheet("color:#9ba8b6;font-size:12px;"
                                 "font-family:'Ubuntu Mono';");
    tl->addWidget(ttl);
    tl->addSpacing(16);
    tl->addWidget(m_statusLabel);
    tl->addStretch();
    outer->addWidget(topBar);

    auto *div = new QFrame(this);
    div->setFrameShape(QFrame::HLine);
    div->setStyleSheet("background:#e4e8ee;max-height:1px;");
    outer->addWidget(div);

    auto *split = new QSplitter(Qt::Vertical, this);
    split->setHandleWidth(1);

    // Map
    m_scene = new QGraphicsScene(0, 0, SW, SH, this);
    m_scene->setBackgroundBrush(QBrush(QColor("#060b10")));
    m_view = new QGraphicsView(m_scene, split);
    m_view->setRenderHint(QPainter::Antialiasing);
    m_view->setStyleSheet("background:#060b10;border:none;");
    m_view->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    m_view->setVerticalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    m_view->setDragMode(QGraphicsView::ScrollHandDrag);

    // Threat table
    m_table = new QTableWidget(0, 6, split);
    m_table->setHorizontalHeaderLabels(
        {"IP", "PROCESS", "THREAT", "SCORE", "CATEGORY", "LAST SEEN"});
    m_table->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_table->setAlternatingRowColors(true);
    m_table->setShowGrid(false);
    m_table->verticalHeader()->setVisible(false);
    m_table->verticalHeader()->setDefaultSectionSize(32);
    m_table->horizontalHeader()->setSectionResizeMode(QHeaderView::Interactive);
    m_table->setColumnWidth(0, 140);
    m_table->setColumnWidth(1, 120);
    m_table->setColumnWidth(2, 90);
    m_table->setColumnWidth(3, 60);
    m_table->setColumnWidth(4, 110);
    m_table->horizontalHeader()->setStretchLastSection(true);

    split->addWidget(m_view);
    split->addWidget(m_table);
    split->setSizes({320, 160});
    split->setStretchFactor(0, 2);
    split->setStretchFactor(1, 1);
    outer->addWidget(split, 1);

    drawBackground();
    m_view->fitInView(m_scene->sceneRect(), Qt::KeepAspectRatio);
}

QPointF ThreatMapTab::geo2scene(double lat, double lon) const
{
    return {(lon + 180.0) / 360.0 * SW, (90.0 - lat) / 180.0 * SH};
}

void ThreatMapTab::drawBackground()
{
    QPen grid(QColor(255, 255, 255, 8), 0.5);
    for (int lat = -60; lat <= 60; lat += 30)
    {
        auto a = geo2scene(lat, -180), b = geo2scene(lat, 180);
        m_scene->addLine(a.x(), a.y(), b.x(), b.y(), grid)->setZValue(0);
    }
    for (int lon = -150; lon <= 180; lon += 30)
    {
        auto a = geo2scene(90, lon), b = geo2scene(-90, lon);
        m_scene->addLine(a.x(), a.y(), b.x(), b.y(), grid)->setZValue(0);
    }

    QColor lc(25, 38, 52, 200);
    QPen lp(QColor(40, 58, 75, 80), 0.5);
    auto land = [&](QPolygonF p)
    { m_scene->addPolygon(p, lp, QBrush(lc))->setZValue(1); };

    land(QPolygonF({geo2scene(70, -140), geo2scene(72, -95), geo2scene(65, -60),
                    geo2scene(47, -53), geo2scene(25, -80), geo2scene(10, -77),
                    geo2scene(20, -105), geo2scene(32, -117), geo2scene(49, -124),
                    geo2scene(70, -140)}));
    land(QPolygonF({geo2scene(12, -72), geo2scene(0, -50), geo2scene(-34, -58),
                    geo2scene(-55, -68), geo2scene(-18, -75), geo2scene(12, -72)}));
    land(QPolygonF({geo2scene(71, 28), geo2scene(55, 24), geo2scene(36, -9),
                    geo2scene(51, 2), geo2scene(71, 28)}));
    land(QPolygonF({geo2scene(37, 10), geo2scene(22, 37), geo2scene(-34, 26),
                    geo2scene(5, -5), geo2scene(37, 10)}));
    land(QPolygonF({geo2scene(72, 60), geo2scene(68, 140), geo2scene(35, 130),
                    geo2scene(8, 78), geo2scene(22, 68), geo2scene(55, 37), geo2scene(72, 60)}));
    land(QPolygonF({geo2scene(-15, 129), geo2scene(-24, 154),
                    geo2scene(-38, 147), geo2scene(-22, 114), geo2scene(-15, 129)}));
    land(QPolygonF({geo2scene(28, 72), geo2scene(28, 88),
                    geo2scene(8, 78), geo2scene(22, 68), geo2scene(28, 72)}));
}

void ThreatMapTab::updateData(const QVector<TrafficEntry> &conns)
{
    m_conns = conns;
    for (const auto &e : conns)
        if (e.isActive())
            ThreatIntel::instance().checkIp(e.destIp);
    rebuildMap();
    rebuildTable();
}

void ThreatMapTab::rebuildMap()
{
    for (auto *it : m_items)
        if (it->scene() == m_scene)
            m_scene->removeItem(it);
    qDeleteAll(m_items);
    m_items.clear();

    // Source: Bhopal
    QPointF src = geo2scene(23.25, 77.40);
    auto *srcG = m_scene->addEllipse(src.x() - 12, src.y() - 12, 24, 24,
                                     QPen(Qt::NoPen), QBrush(QColor(29, 110, 245, 40)));
    srcG->setZValue(4);
    m_items.append(srcG);
    auto *srcD = m_scene->addEllipse(src.x() - 6, src.y() - 6, 12, 12,
                                     QPen(Qt::NoPen), QBrush(QColor("#6366f1")));
    srcD->setZValue(5);
    m_items.append(srcD);

    int threats = 0, total = 0;
    QSet<QString> plotted;

    for (const auto &e : m_conns)
    {
        if (!e.isActive())
            continue;
        if (plotted.contains(e.destIp))
            continue;
        plotted.insert(e.destIp);
        total++;

        ThreatInfo ti = ThreatIntel::instance().getInfo(e.destIp);
        QColor col = ThreatIntel::instance().colorForLevel(ti.level);
        if (ti.level != ThreatLevel::Clean)
            threats++;

        // We don't have geo for connections without routes
        // Plot based on IP range heuristics
        // For display: use a fixed position based on IP hash
        QHostAddress addr(e.destIp);
        quint32 ipv4 = addr.toIPv4Address();
        if (!ipv4)
            continue; // skip invalid or IPv6 addresses

        // Map IP to approximate region
        double lat = 0, lon = 0;
        quint8 first = (ipv4 >> 24) & 0xFF;
        if (first >= 1 && first <= 50)
        {
            lat = 37;
            lon = -95;
        } // US
        else if (first >= 51 && first <= 100)
        {
            lat = 51;
            lon = 10;
        } // Europe
        else if (first >= 101 && first <= 150)
        {
            lat = 35;
            lon = 105;
        } // Asia
        else if (first >= 151 && first <= 200)
        {
            lat = -25;
            lon = 135;
        } // Aus/Pacific
        else
        {
            lat = 0;
            lon = 20;
        } // Africa/other

        // Add some variation based on IP
        lat += ((ipv4 >> 16) & 0xFF) / 255.0 * 20 - 10;
        lon += ((ipv4 >> 8) & 0xFF) / 255.0 * 30 - 15;

        QPointF dst = geo2scene(lat, lon);

        // Arc
        QPainterPath path;
        path.moveTo(src);
        QPointF mid = (src + dst) / 2.0;
        mid.setY(mid.y() - QLineF(src, dst).length() * 0.2);
        path.quadTo(mid, dst);

        double opacity = ti.level != ThreatLevel::Clean ? 0.8 : 0.2;
        auto *arc = m_scene->addPath(path,
                                     QPen(col, ti.level != ThreatLevel::Clean ? 1.5 : 0.5));
        arc->setOpacity(opacity);
        arc->setZValue(3);
        m_items.append(arc);

        // Dest dot
        double r = ti.level != ThreatLevel::Clean ? 7.0 : 4.0;
        if (ti.level != ThreatLevel::Clean)
        {
            auto *glow = m_scene->addEllipse(
                dst.x() - r * 2, dst.y() - r * 2, r * 4, r * 4,
                QPen(Qt::NoPen),
                QBrush(QColor(col.red(), col.green(), col.blue(), 40)));
            glow->setZValue(4);
            m_items.append(glow);
        }
        auto *dot = m_scene->addEllipse(
            dst.x() - r, dst.y() - r, r * 2, r * 2,
            QPen(Qt::NoPen), QBrush(col));
        dot->setZValue(5);
        m_items.append(dot);
    }

    m_statusLabel->setText(
        QString("%1 connections  |  %2 threats detected")
            .arg(total)
            .arg(threats));
    m_view->fitInView(m_scene->sceneRect(), Qt::KeepAspectRatio);
}

void ThreatMapTab::rebuildTable()
{
    // Only show threats
    QVector<QPair<ThreatInfo, TrafficEntry>> threats;
    QSet<QString> seen;
    for (const auto &e : m_conns)
    {
        if (!e.isActive() || seen.contains(e.destIp))
            continue;
        seen.insert(e.destIp);
        ThreatInfo ti = ThreatIntel::instance().getInfo(e.destIp);
        if (ti.level != ThreatLevel::Clean)
            threats.append({ti, e});
    }

    m_table->setRowCount(threats.size());
    for (int i = 0; i < threats.size(); ++i)
    {
        const ThreatInfo &ti = threats[i].first;
        const TrafficEntry &e = threats[i].second;
        QColor col = ThreatIntel::instance().colorForLevel(ti.level);

        auto item = [](const QString &t, const QColor &c) -> QTableWidgetItem *
        {
            auto*it=new QTableWidgetItem(t);
            it->setForeground(QBrush(c));
            it->setFlags(Qt::ItemIsEnabled|Qt::ItemIsSelectable);
            it->setBackground(QBrush(QColor("#fef2f2")));
            return it; };

        QString ts = ti.lastSeen > 0 ? QDateTime::fromSecsSinceEpoch(ti.lastSeen).toString("hh:mm:ss") : "-";

        m_table->setItem(i, 0, item(ti.ip, QColor("#ef4444")));
        m_table->setItem(i, 1, item(e.process, QColor("#1e2a3a")));
        m_table->setItem(i, 2, item(ThreatIntel::instance().labelForLevel(ti.level), col));
        m_table->setItem(i, 3, item(QString::number(ti.score), col));
        m_table->setItem(i, 4, item(ti.category, QColor("#5c6b7f")));
        m_table->setItem(i, 5, item(ts, QColor("#9ba8b6")));
    }
}