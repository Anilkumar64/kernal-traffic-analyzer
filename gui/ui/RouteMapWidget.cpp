#include "RouteMapWidget.h"
#include "Style.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QFrame>
#include <QSplitter>
#include <QGraphicsPathItem>
#include <QPainterPath>
#include <QPen>
#include <QBrush>
#include <QFont>
#include <QMouseEvent>
#include <QtMath>

// ================================================================
// Connection colors — distinct, readable on dark bg
// ================================================================
const QStringList RouteMapWidget::COLORS = {
    "#3794ff", "#4ec9b0", "#ce9178", "#c586c0",
    "#dcdcaa", "#9cdcfe", "#f44747", "#4ec9b0",
};

QColor RouteMapWidget::connColor(int idx) const {
    return QColor(COLORS[idx % COLORS.size()]);
}

// ================================================================
// ConnDot — animated travelling packet
// ================================================================
ConnDot::ConnDot(const QVector<QPointF> &pts,
                 const QColor &color,
                 bool large,
                 QGraphicsScene *scene)
    : QGraphicsEllipseItem(large ? -5 : -3,
                           large ? -5 : -3,
                           large ? 10  :  6,
                           large ? 10  :  6)
    , m_pts(pts)
{
    setBrush(QBrush(large ? QColor("#ffffff") : color.lighter(130)));
    setPen(QPen(color, large ? 2.0 : 1.2));
    setZValue(50);
    scene->addItem(this);
    m_timer = new QTimer(this);
    m_timer->setInterval(16);
    connect(m_timer, &QTimer::timeout, this, &ConnDot::tick);
}

void ConnDot::start() { if (m_pts.size() >= 2) m_timer->start(); }
void ConnDot::stop()  { m_timer->stop(); }

void ConnDot::tick()
{
    if (m_pts.size() < 2) return;
    m_t += m_speed;
    if (m_t >= 1.0) {
        m_t = 0.0;
        m_seg = (m_seg + 1) % (m_pts.size() - 1);
    }
    setPos(m_pts[m_seg] + (m_pts[m_seg + 1] - m_pts[m_seg]) * m_t);
}

// ================================================================
// Geo helpers
// ================================================================
QPointF RouteMapWidget::geo2scene(double lat, double lon) const
{
    return QPointF((lon + 180.0) / 360.0 * SW,
                   (90.0 - lat)  / 180.0 * SH);
}

double RouteMapWidget::haversine(double la1, double lo1,
                                  double la2, double lo2) const
{
    const double R = 6371.0;
    double dLa = qDegreesToRadians(la2 - la1);
    double dLo = qDegreesToRadians(lo2 - lo1);
    double a = qSin(dLa/2)*qSin(dLa/2) +
               qCos(qDegreesToRadians(la1)) *
               qCos(qDegreesToRadians(la2)) *
               qSin(dLo/2)*qSin(dLo/2);
    return R * 2.0 * qAtan2(qSqrt(a), qSqrt(1.0 - a));
}

// ================================================================
// Constructor
// ================================================================
RouteMapWidget::RouteMapWidget(QWidget *parent) : QWidget(parent)
{
    buildLayout();
}

// ================================================================
// buildLayout
// ================================================================
void RouteMapWidget::buildLayout()
{
    auto *outer = new QVBoxLayout(this);
    outer->setContentsMargins(0, 0, 0, 0);
    outer->setSpacing(0);

    // ── Top bar ──────────────────────────────────────────────────
    auto *bar = new QWidget(this);
    bar->setObjectName("TopBar");
    bar->setFixedHeight(56);
    auto *bl = new QHBoxLayout(bar);
    bl->setContentsMargins(20, 0, 20, 0);
    bl->setSpacing(12);

    auto *ttl = new QLabel("Live Route Map", bar);
    ttl->setStyleSheet(
        "color:#ffffff; font-size:16px; font-weight:600;"
        "font-family:'Segoe UI','Ubuntu',Arial,sans-serif;");

    auto *hint = new QLabel("Click a connection in the legend to highlight its path", bar);
    hint->setStyleSheet(
        "color:#8a8a8a; font-size:13px;"
        "font-family:'Segoe UI','Ubuntu',Arial,sans-serif;");

    bl->addWidget(ttl);
    bl->addWidget(hint);
    bl->addStretch();
    outer->addWidget(bar);

    // divider
    auto mkHLine = [&](QWidget *parent) {
        auto *f = new QFrame(parent);
        f->setFrameShape(QFrame::HLine);
        f->setStyleSheet("background:#333333; max-height:1px; border:none;");
        return f;
    };
    outer->addWidget(mkHLine(this));

    // ── Main splitter: left info panel | map ─────────────────────
    auto *split = new QSplitter(Qt::Horizontal, this);
    split->setHandleWidth(1);
    split->setStyleSheet("QSplitter::handle { background:#333333; }");

    // ── Left info panel ──────────────────────────────────────────
    m_leftPanel = new QWidget(split);
    m_leftPanel->setFixedWidth(220);
    m_leftPanel->setStyleSheet("background:#252526; border:none;");
    auto *lv = new QVBoxLayout(m_leftPanel);
    lv->setContentsMargins(0, 0, 0, 0);
    lv->setSpacing(0);

    auto mkPanelSection = [&](const QString &title) {
        auto *hdr = new QWidget(m_leftPanel);
        hdr->setFixedHeight(36);
        hdr->setStyleSheet("background:#2d2d2d; border-bottom:1px solid #333333;");
        auto *hl = new QHBoxLayout(hdr);
        hl->setContentsMargins(14, 0, 14, 0);
        auto *lbl = new QLabel(title, hdr);
        lbl->setStyleSheet(
            "color:#555555; font-size:11px; font-weight:700;"
            "letter-spacing:1.5px; text-transform:uppercase;"
            "background:transparent;");
        hl->addWidget(lbl);
        return hdr;
    };

    // DATA SOVEREIGNTY
    lv->addWidget(mkPanelSection("DATA SOVEREIGNTY"));
    m_sovereignty = new QLabel("—", m_leftPanel);
    m_sovereignty->setWordWrap(true);
    m_sovereignty->setContentsMargins(14, 10, 14, 10);
    m_sovereignty->setStyleSheet(
        "color:#cccccc; font-size:13px; line-height:1.5;"
        "font-family:'Segoe UI','Ubuntu',Arial,sans-serif;"
        "background:transparent;");
    lv->addWidget(m_sovereignty);

    auto *divSov = new QFrame(m_leftPanel);
    divSov->setFrameShape(QFrame::HLine);
    divSov->setStyleSheet("background:#333333; max-height:1px; border:none;");
    lv->addWidget(divSov);

    // LATENCY BLAME
    lv->addWidget(mkPanelSection("LATENCY BLAME"));
    m_latency = new QLabel("Select a connection", m_leftPanel);
    m_latency->setWordWrap(true);
    m_latency->setContentsMargins(14, 10, 14, 10);
    m_latency->setStyleSheet(
        "color:#cccccc; font-size:13px; line-height:1.5;"
        "font-family:'Segoe UI','Ubuntu',Arial,sans-serif;"
        "background:transparent;");
    lv->addWidget(m_latency);

    auto *divLat = new QFrame(m_leftPanel);
    divLat->setFrameShape(QFrame::HLine);
    divLat->setStyleSheet("background:#333333; max-height:1px; border:none;");
    lv->addWidget(divLat);

    // RTT Legend (in left panel, bottom)
    lv->addStretch();

    auto *divRtt = new QFrame(m_leftPanel);
    divRtt->setFrameShape(QFrame::HLine);
    divRtt->setStyleSheet("background:#333333; max-height:1px; border:none;");
    lv->addWidget(divRtt);

    lv->addWidget(mkPanelSection("RTT LEGEND"));

    struct RttEntry { QString label; QString color; };
    QList<RttEntry> rtts = {
        {"fast  < 50ms",   "#4ec9b0"},
        {"med   < 150ms",  "#ce9178"},
        {"slow  > 150ms",  "#f44747"},
        {"packet in transit", "#cccccc"},
    };
    for (const auto &r : rtts) {
        auto *row = new QWidget(m_leftPanel);
        row->setStyleSheet("background:transparent;");
        auto *rl = new QHBoxLayout(row);
        rl->setContentsMargins(14, 5, 14, 5);
        rl->setSpacing(10);
        auto *dot = new QLabel(row);
        dot->setFixedSize(9, 9);
        dot->setStyleSheet(
            QString("background:%1; border-radius:4px;").arg(r.color));
        auto *lbl = new QLabel(r.label, row);
        lbl->setStyleSheet(
            "color:#8a8a8a; font-size:12px;"
            "font-family:'Segoe UI','Ubuntu',Arial,sans-serif;"
            "background:transparent;");
        rl->addWidget(dot);
        rl->addWidget(lbl);
        rl->addStretch();
        lv->addWidget(row);
    }
    lv->addSpacing(8);

    // ── Map view ─────────────────────────────────────────────────
    m_scene = new QGraphicsScene(0, 0, SW, SH, this);
    m_scene->setBackgroundBrush(QBrush(QColor("#1a1a1a")));

    m_view = new QGraphicsView(m_scene, split);
    m_view->setRenderHints(QPainter::Antialiasing | QPainter::SmoothPixmapTransform);
    m_view->setDragMode(QGraphicsView::ScrollHandDrag);
    m_view->setStyleSheet("background:#1a1a1a; border:none;");
    m_view->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    m_view->setVerticalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    m_view->viewport()->setCursor(Qt::ArrowCursor);

    split->addWidget(m_leftPanel);
    split->addWidget(m_view);
    split->setStretchFactor(0, 0);
    split->setStretchFactor(1, 1);
    outer->addWidget(split, 1);

    // ── Bottom legend bar ─────────────────────────────────────────
    outer->addWidget(mkHLine(this));
    m_legendBar = new QWidget(this);
    m_legendBar->setFixedHeight(52);
    m_legendBar->setStyleSheet("background:#252526;");
    outer->addWidget(m_legendBar);

    drawBackground();
    m_view->fitInView(m_scene->sceneRect(), Qt::KeepAspectRatio);
}

// ================================================================
// drawBackground — clean dark world map matching Azure style
// ================================================================
void RouteMapWidget::drawBackground()
{
    // Subtle grid — very faint
    QPen grid(QColor(255, 255, 255, 8), 0.4);
    for (int lat = -60; lat <= 60; lat += 30) {
        QPointF a = geo2scene(lat, -180), b = geo2scene(lat, 180);
        m_scene->addLine(a.x(), a.y(), b.x(), b.y(), grid)->setZValue(0);
    }
    for (int lon = -150; lon <= 180; lon += 30) {
        QPointF a = geo2scene(90, lon), b = geo2scene(-90, lon);
        m_scene->addLine(a.x(), a.y(), b.x(), b.y(), grid)->setZValue(0);
    }

    // Landmass color — matches Azure's dark slate continents
    QColor lc(42, 50, 62, 230);
    QPen   lp(QColor(58, 70, 85, 120), 0.6);
    auto land = [&](QPolygonF p) {
        m_scene->addPolygon(p, lp, QBrush(lc))->setZValue(1);
    };

    // North America
    land(QPolygonF({geo2scene(70,-140),geo2scene(72,-95),geo2scene(65,-60),
                    geo2scene(47,-53),geo2scene(25,-80),geo2scene(15,-85),
                    geo2scene(10,-77),geo2scene(20,-105),geo2scene(32,-117),
                    geo2scene(49,-124),geo2scene(60,-140),geo2scene(70,-140)}));
    // South America
    land(QPolygonF({geo2scene(12,-72),geo2scene(10,-62),geo2scene(0,-50),
                    geo2scene(-10,-37),geo2scene(-23,-43),geo2scene(-34,-58),
                    geo2scene(-55,-68),geo2scene(-45,-75),geo2scene(-18,-75),
                    geo2scene(5,-77),geo2scene(12,-72)}));
    // Europe
    land(QPolygonF({geo2scene(71,28),geo2scene(60,28),geo2scene(55,24),
                    geo2scene(47,8),geo2scene(36,5),geo2scene(36,-9),
                    geo2scene(43,-9),geo2scene(51,2),geo2scene(58,5),
                    geo2scene(70,25),geo2scene(71,28)}));
    // Africa
    land(QPolygonF({geo2scene(37,10),geo2scene(38,24),geo2scene(22,37),
                    geo2scene(12,44),geo2scene(5,41),geo2scene(-5,40),
                    geo2scene(-26,34),geo2scene(-34,26),geo2scene(-26,16),
                    geo2scene(5,2),geo2scene(5,-5),geo2scene(15,-17),
                    geo2scene(28,-13),geo2scene(37,10)}));
    // Asia
    land(QPolygonF({geo2scene(72,60),geo2scene(73,100),geo2scene(68,140),
                    geo2scene(55,135),geo2scene(35,130),geo2scene(22,120),
                    geo2scene(10,104),geo2scene(1,104),geo2scene(8,78),
                    geo2scene(22,68),geo2scene(24,57),geo2scene(30,48),
                    geo2scene(40,36),geo2scene(42,28),geo2scene(55,37),
                    geo2scene(60,60),geo2scene(72,60)}));
    // Australia
    land(QPolygonF({geo2scene(-15,129),geo2scene(-12,136),geo2scene(-16,146),
                    geo2scene(-24,154),geo2scene(-38,147),geo2scene(-32,133),
                    geo2scene(-32,122),geo2scene(-22,114),geo2scene(-15,129)}));
    // India
    land(QPolygonF({geo2scene(28,72),geo2scene(28,88),geo2scene(22,92),
                    geo2scene(8,78),geo2scene(22,68),geo2scene(28,72)}));
    // Greenland
    land(QPolygonF({geo2scene(83,-30),geo2scene(76,-18),geo2scene(70,-22),
                    geo2scene(76,-68),geo2scene(83,-48),geo2scene(83,-30)}));
    // Japan
    land(QPolygonF({geo2scene(45,141),geo2scene(40,141),geo2scene(33,130),
                    geo2scene(34,132),geo2scene(42,140),geo2scene(45,141)}));
    // UK
    land(QPolygonF({geo2scene(58,-5),geo2scene(60,-1),geo2scene(57,0),
                    geo2scene(51,1),geo2scene(50,-5),geo2scene(54,-3),
                    geo2scene(58,-5)}));
    // Scandinavia
    land(QPolygonF({geo2scene(71,28),geo2scene(65,14),geo2scene(57,8),
                    geo2scene(58,5),geo2scene(62,6),geo2scene(70,25),
                    geo2scene(71,28)}));
}

// ================================================================
// rebuildLegend — bottom connection bar
// ================================================================
void RouteMapWidget::rebuildLegend()
{
    if (auto *old = m_legendBar->layout()) {
        while (auto *it = old->takeAt(0)) {
            if (it->widget()) it->widget()->deleteLater();
            delete it;
        }
        delete old;
    }

    auto *lay = new QHBoxLayout(m_legendBar);
    lay->setContentsMargins(20, 0, 16, 0);
    lay->setSpacing(0);

    // Label
    auto *hdrLbl = new QLabel("CONNECTIONS", m_legendBar);
    hdrLbl->setStyleSheet(
        "color:#555555; font-size:11px; font-weight:700;"
        "letter-spacing:1.5px; margin-right:16px;"
        "font-family:'Segoe UI','Ubuntu',Arial,sans-serif;");
    lay->addWidget(hdrLbl);

    for (int i = 0; i < m_connItems.size(); ++i) {
        const ConnItem &ci = m_connItems[i];

        auto *entry = new QWidget(m_legendBar);
        entry->setObjectName("LegendEntry");
        entry->setProperty("ipkey", ci.ip);
        entry->setCursor(Qt::PointingHandCursor);
        entry->setStyleSheet(ci.ip == m_selIp
            ? "background:#37373d; border-radius:4px;"
            : "background:transparent; border-radius:4px;");

        auto *el = new QHBoxLayout(entry);
        el->setContentsMargins(10, 0, 10, 0);
        el->setSpacing(8);

        auto *dot = new QLabel(entry);
        dot->setFixedSize(8, 8);
        dot->setStyleSheet(
            QString("background:%1; border-radius:4px;")
                .arg(ci.ready ? ci.color.name() : "#555555"));

        auto *info = new QVBoxLayout();
        info->setSpacing(1);

        auto *nm = new QLabel(ci.label, entry);
        nm->setStyleSheet(
            QString("color:%1; font-size:13px; font-weight:500;"
                    "font-family:'Segoe UI','Ubuntu',Arial,sans-serif;")
                .arg(ci.ready ? ci.color.name() : "#8a8a8a"));

        auto *sub = new QLabel(
            QString("%1  %2").arg(ci.rate, ci.proto), entry);
        sub->setStyleSheet(
            "color:#555555; font-size:11px;"
            "font-family:'Segoe UI','Ubuntu',Arial,sans-serif;");

        info->addWidget(nm);
        info->addWidget(sub);
        el->addWidget(dot, 0, Qt::AlignVCenter);
        el->addLayout(info);

        entry->installEventFilter(this);
        lay->addWidget(entry);

        if (i < m_connItems.size() - 1) {
            auto *sep = new QFrame(m_legendBar);
            sep->setFrameShape(QFrame::VLine);
            sep->setStyleSheet(
                "background:#333333; max-width:1px; border:none;");
            sep->setFixedHeight(30);
            lay->addWidget(sep);
            lay->addSpacing(4);
        }
    }

    lay->addStretch();
}

// ================================================================
// eventFilter — legend click
// ================================================================
bool RouteMapWidget::eventFilter(QObject *obj, QEvent *ev)
{
    if (ev->type() == QEvent::MouseButtonPress) {
        auto *w = qobject_cast<QWidget*>(obj);
        if (w && w->objectName() == "LegendEntry") {
            selectIp(w->property("ipkey").toString());
            return true;
        }
    }
    return QWidget::eventFilter(obj, ev);
}

// ================================================================
// rebuildList
// ================================================================
void RouteMapWidget::rebuildList()
{
    m_connItems.clear();

    QMap<QString, const TrafficEntry*> seen;
    for (const auto &e : m_conns)
        if (e.isActive() && !seen.contains(e.destIp))
            seen.insert(e.destIp, &e);

    bool selExists = false;
    int ci = 0;

    for (auto it = seen.begin(); it != seen.end(); ++it) {
        const QString &dip = it.key();
        if (dip.startsWith("192.168.") || dip.startsWith("10.") ||
            dip.startsWith("172.")     || dip.startsWith("127.") ||
            dip.startsWith("169.254")  || dip == "0.0.0.0") continue;

        const TrafficEntry &e = *it.value();
        bool ready = m_routes.contains(e.destIp) &&
                     m_routes[e.destIp].isReady();

        QString dom = (e.domain.isEmpty() || e.domain == "-")
                    ? e.destIp : e.domain;
        if (dom.length() > 22) dom = dom.left(19) + "...";

        QString rate = e.formatRate(e.rateInBps);
        if (rate == "-") rate = e.formatRate(e.rateOutBps);
        if (rate == "-") rate = e.formatBytes(e.bytesIn + e.bytesOut);

        ConnItem item;
        item.ip    = e.destIp;
        item.label = dom;
        item.rate  = rate;
        item.proto = e.protocol;
        item.color = connColor(ci);
        item.ready = ready;
        m_connItems.append(item);

        if (e.destIp == m_selIp) selExists = true;
        ci++;
    }

    if (!selExists) {
        m_selIp = "";
        for (const auto &item : m_connItems)
            if (item.ready) { m_selIp = item.ip; break; }
    }

    rebuildLegend();
}

// ================================================================
// clearRouteItems
// ================================================================
void RouteMapWidget::clearRouteItems()
{
    for (auto *d : m_dots) d->stop();
    m_dots.clear();
    for (auto *it : m_routeItems)
        if (it && it->scene() == m_scene)
            m_scene->removeItem(it);
    qDeleteAll(m_routeItems);
    m_routeItems.clear();
}

// ================================================================
// redrawRoutes — clean Azure-style arcs
// ================================================================
void RouteMapWidget::redrawRoutes()
{
    clearRouteItems();

    for (int ci = 0; ci < m_connItems.size(); ++ci) {
        const ConnItem &citem = m_connItems[ci];
        if (!citem.ready) continue;

        const RouteEntry &re   = m_routes[citem.ip];
        bool              active = (citem.ip == m_selIp);
        QColor            col    = citem.color;

        // collect valid geo hops
        QVector<QPointF>         pts;
        QVector<const RouteHop*> hops;
        for (const auto &h : re.hops) {
            if (!h.hasGeo()) continue;
            if (qAbs(h.lat) < 0.1 && qAbs(h.lon) < 0.1) continue;
            pts.append(geo2scene(h.lat, h.lon));
            hops.append(&h);
        }
        if (pts.size() < 2) continue;

        // draw arc segments
        for (int i = 0; i + 1 < pts.size(); ++i) {
            QPointF p1 = pts[i], p2 = pts[i + 1];
            QPointF mid = (p1 + p2) / 2.0;
            mid.setY(mid.y() - QLineF(p1, p2).length() * 0.20);

            QPainterPath path;
            path.moveTo(p1);
            path.quadTo(mid, p2);

            if (active) {
                // Active: solid bright line
                QPen pen(col, 2.0);
                pen.setCapStyle(Qt::RoundCap);
                auto *arc = m_scene->addPath(path, pen);
                arc->setOpacity(1.0);
                arc->setZValue(10);
                m_routeItems.append(arc);

                // distance label
                if (i + 1 < (int)hops.size()) {
                    double km = haversine(hops[i]->lat, hops[i]->lon,
                                          hops[i+1]->lat, hops[i+1]->lon);
                    if (km > 300) {
                        QString s = km > 999
                            ? QString("%1K km").arg(int(km / 1000))
                            : QString("%1 km").arg(int(km));
                        auto *t = m_scene->addText(s);
                        t->setDefaultTextColor(QColor("#555555"));
                        t->setFont(QFont("Segoe UI", 7));
                        t->setPos(mid.x() - 18, mid.y() - 16);
                        t->setZValue(12);
                        m_routeItems.append(t);
                    }
                }
            } else {
                // Inactive: very faint dashed
                QColor dc = col;
                dc.setAlpha(45);
                QPen pen(dc, 0.8, Qt::DashLine);
                auto *arc = m_scene->addPath(path, pen);
                arc->setZValue(8);
                m_routeItems.append(arc);
            }
        }

        // draw hop nodes
        for (int i = 0; i < (int)hops.size(); ++i) {
            const RouteHop *h = hops[i];
            QPointF pt = pts[i];
            bool first = (i == 0), last = (i == (int)hops.size() - 1);
            double r = (first || last) ? 5.0 : 3.5;
            QColor dc = active ? QColor(h->rttColorHex()) : col;

            if (active) {
                // glow ring
                auto *g = m_scene->addEllipse(
                    pt.x()-r*2.0, pt.y()-r*2.0, r*4.0, r*4.0,
                    QPen(Qt::NoPen),
                    QBrush(QColor(dc.red(), dc.green(), dc.blue(), 28)));
                g->setZValue(9);
                m_routeItems.append(g);

                // filled dot
                auto *dot = m_scene->addEllipse(
                    pt.x()-r, pt.y()-r, r*2, r*2,
                    QPen(QColor(255,255,255,60), 0.8),
                    QBrush(dc));
                dot->setZValue(11);
                m_routeItems.append(dot);

                // label
                bool hasCity = !h->city.isEmpty() &&
                               h->city != "-" && h->city != "0";
                if (first) {
                    auto *lbl = m_scene->addText("you");
                    lbl->setDefaultTextColor(col);
                    lbl->setFont(QFont("Segoe UI", 8));
                    double lx = qBound(2.0,
                        pt.x() - lbl->boundingRect().width() / 2.0,
                        SW - lbl->boundingRect().width() - 2.0);
                    lbl->setPos(lx, pt.y() - r - 18);
                    lbl->setZValue(13);
                    m_routeItems.append(lbl);
                } else if (hasCity) {
                    QString rttS = h->rttMs > 0
                        ? QString("  %1ms").arg(int(h->rttMs)) : "";
                    auto *lbl = m_scene->addText(h->city + rttS);
                    lbl->setDefaultTextColor(QColor("#8a8a8a"));
                    lbl->setFont(QFont("Segoe UI", 8));
                    double lx = qBound(2.0,
                        pt.x() - lbl->boundingRect().width() / 2.0,
                        SW - lbl->boundingRect().width() - 2.0);
                    lbl->setPos(lx, pt.y() - r - 18);
                    lbl->setZValue(13);
                    m_routeItems.append(lbl);
                }
            } else {
                // inactive node — tiny dim dot
                QColor dc2 = col;
                dc2.setAlpha(50);
                auto *dot = m_scene->addEllipse(
                    pt.x()-2.5, pt.y()-2.5, 5.0, 5.0,
                    QPen(Qt::NoPen),
                    QBrush(dc2));
                dot->setZValue(8);
                m_routeItems.append(dot);
            }
        }

        // animated packet dot
        if (pts.size() >= 2) {
            auto *cd = new ConnDot(pts, col, active, m_scene);
            cd->setZValue(20);
            cd->start();
            m_dots.append(cd);
            m_routeItems.append(cd);
        }
    }

    m_view->fitInView(m_scene->sceneRect(), Qt::KeepAspectRatio);
}

// ================================================================
// updateInfoPanels
// ================================================================
void RouteMapWidget::updateInfoPanels(const QString &ip)
{
    if (!m_routes.contains(ip) || !m_routes[ip].isReady()) {
        m_sovereignty->setText("Route pending...");
        m_sovereignty->setStyleSheet(
            "color:#555555; font-size:13px; font-style:italic;"
            "font-family:'Segoe UI','Ubuntu',Arial,sans-serif;"
            "background:transparent;");
        m_latency->setText("Route pending...");
        m_latency->setStyleSheet(
            "color:#555555; font-size:13px; font-style:italic;"
            "font-family:'Segoe UI','Ubuntu',Arial,sans-serif;"
            "background:transparent;");
        return;
    }
    const RouteEntry &re = m_routes[ip];

    // Sovereignty
    QStringList countries;
    QSet<QString> sc;
    for (const auto &h : re.hops)
        if (!h.country.isEmpty() && h.country != "-" &&
            !sc.contains(h.cc)) {
            sc.insert(h.cc);
            countries << h.country;
        }

    if (countries.isEmpty()) {
        m_sovereignty->setText("No geo data");
        m_sovereignty->setStyleSheet(
            "color:#555555; font-size:13px; font-style:italic;"
            "font-family:'Segoe UI','Ubuntu',Arial,sans-serif;"
            "background:transparent;");
    } else {
        m_sovereignty->setText(countries.join("  →  "));
        m_sovereignty->setStyleSheet(
            "color:#cccccc; font-size:13px; line-height:1.6;"
            "font-family:'Segoe UI','Ubuntu',Arial,sans-serif;"
            "background:transparent;");
    }

    // Latency blame
    double worst = 0; int wi = -1;
    for (int i = 1; i < re.hops.size(); ++i) {
        double d = re.hops[i].rttMs - re.hops[i-1].rttMs;
        if (d > worst) { worst = d; wi = i; }
    }
    if (wi > 0) {
        const RouteHop &f = re.hops[wi-1], &t2 = re.hops[wi];
        double total = re.hops.last().rttMs;
        int pct = total > 0 ? int(worst / total * 100) : 0;
        QString fc = (f.city.isEmpty()  || f.city  == "-") ? f.hopIp  : f.city;
        QString tc = (t2.city.isEmpty() || t2.city == "-") ? t2.hopIp : t2.city;
        double km = (f.hasGeo() && t2.hasGeo())
            ? haversine(f.lat, f.lon, t2.lat, t2.lon) : 0;

        QString txt = QString("%1\n→ %2\n+%3ms  (%4%)")
            .arg(fc, tc)
            .arg(worst, 0, 'f', 1)
            .arg(pct);
        if (km > 0) txt += QString("\n%1 km").arg(int(km));

        m_latency->setText(txt);
        m_latency->setStyleSheet(
            "color:#cccccc; font-size:13px; line-height:1.6;"
            "font-family:'Segoe UI','Ubuntu',Arial,sans-serif;"
            "background:transparent;");
    } else {
        m_latency->setText("Insufficient data");
        m_latency->setStyleSheet(
            "color:#555555; font-size:13px; font-style:italic;"
            "font-family:'Segoe UI','Ubuntu',Arial,sans-serif;"
            "background:transparent;");
    }
}

// ================================================================
// selectIp
// ================================================================
void RouteMapWidget::selectIp(const QString &ip)
{
    m_selIp = ip;
    rebuildLegend();
    redrawRoutes();
    updateInfoPanels(ip);
}

// ================================================================
// updateRoutes — called every second from MainWindow
// ================================================================
void RouteMapWidget::updateRoutes(
    const QMap<QString, RouteEntry> &routes,
    const QVector<TrafficEntry> &conns)
{
    m_routes = routes;
    m_conns  = conns;
    rebuildList();
    redrawRoutes();
}
