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
// Colors
// ================================================================
const QStringList RouteMapWidget::COLORS = {
    "#388bfd", "#3fb950", "#f0883e", "#bc8cff",
    "#ff6b6b", "#79c0ff", "#56d364", "#ffa657",
};

QColor RouteMapWidget::connColor(int idx) const {
    return QColor(COLORS[idx % COLORS.size()]);
}

// ================================================================
// ConnDot
// ================================================================
ConnDot::ConnDot(const QVector<QPointF> &pts,
                 const QColor &color,
                 bool large,
                 QGraphicsScene *scene)
    : QGraphicsEllipseItem(large ? -7 : -4,
                           large ? -7 : -4,
                           large ? 14  :  8,
                           large ? 14  :  8)
    , m_pts(pts)
{
    setBrush(QBrush(large ? Qt::white : color.lighter(150)));
    setPen(QPen(color, large ? 2.5 : 1.5));
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

    // top bar
    auto *bar = new QWidget(this);
    bar->setObjectName("TopBar");
    bar->setFixedHeight(52);
    auto *bl = new QHBoxLayout(bar);
    bl->setContentsMargins(16, 0, 16, 0);
    auto *ttl = new QLabel("Live Route Map", bar);
    ttl->setStyleSheet("color:#e6edf3;font-size:14px;font-weight:600;"
                       "font-family:'Ubuntu Mono';");
    auto *hint = new QLabel(
        "Click a connection below to highlight its path", bar);
    hint->setStyleSheet("color:#484f58;font-size:11px;"
                        "font-family:'Ubuntu Mono';");
    bl->addWidget(ttl);
    bl->addSpacing(12);
    bl->addWidget(hint);
    bl->addStretch();
    outer->addWidget(bar);

    auto *hline = new QFrame(this);
    hline->setFrameShape(QFrame::HLine);
    hline->setStyleSheet("background:#30363d;max-height:1px;");
    outer->addWidget(hline);

    // splitter
    auto *split = new QSplitter(Qt::Horizontal, this);
    split->setHandleWidth(1);
    split->setStyleSheet("QSplitter::handle{background:#30363d;}");

    // left info panel
    m_leftPanel = new QWidget(split);
    m_leftPanel->setFixedWidth(200);
    m_leftPanel->setStyleSheet("background:#161b22;");
    auto *ll = new QVBoxLayout(m_leftPanel);
    ll->setContentsMargins(0, 0, 0, 0);
    ll->setSpacing(0);

    auto mkDiv = [&]() {
        auto *f = new QFrame(m_leftPanel);
        f->setFrameShape(QFrame::HLine);
        f->setStyleSheet("background:#30363d;max-height:1px;");
        return f;
    };
    auto mkSec = [&](const QString &t) {
        auto *l = new QLabel(t, m_leftPanel);
        l->setObjectName("SectionTitle");
        l->setFixedHeight(30);
        return l;
    };

    ll->addWidget(mkSec("  DATA SOVEREIGNTY"));
    ll->addWidget(mkDiv());
    m_sovereignty = new QLabel("-", m_leftPanel);
    m_sovereignty->setWordWrap(true);
    m_sovereignty->setStyleSheet(
        "color:#8b949e;font-size:11px;padding:8px 12px;"
        "font-family:'Ubuntu Mono';");
    ll->addWidget(m_sovereignty);

    ll->addWidget(mkDiv());
    ll->addWidget(mkSec("  LATENCY BLAME"));
    m_latency = new QLabel("Select a connection", m_leftPanel);
    m_latency->setWordWrap(true);
    m_latency->setStyleSheet(
        "color:#8b949e;font-size:11px;padding:8px 12px;"
        "font-family:'Ubuntu Mono';");
    ll->addWidget(m_latency);
    ll->addStretch();

    // map
    m_scene = new QGraphicsScene(0, 0, SW, SH, this);
    m_scene->setBackgroundBrush(QBrush(QColor("#0d1117")));

    m_view = new QGraphicsView(m_scene, split);
    m_view->setRenderHint(QPainter::Antialiasing);
    m_view->setDragMode(QGraphicsView::ScrollHandDrag);
    m_view->setStyleSheet("background:#0d1117;border:none;");
    m_view->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    m_view->setVerticalScrollBarPolicy(Qt::ScrollBarAlwaysOff);

    split->addWidget(m_leftPanel);
    split->addWidget(m_view);
    split->setStretchFactor(0, 0);
    split->setStretchFactor(1, 1);
    outer->addWidget(split, 1);

    // bottom divider
    auto *bline = new QFrame(this);
    bline->setFrameShape(QFrame::HLine);
    bline->setStyleSheet("background:#30363d;max-height:1px;");
    outer->addWidget(bline);

    // legend bar
    m_legendBar = new QWidget(this);
    m_legendBar->setFixedHeight(56);
    m_legendBar->setStyleSheet("background:#161b22;");
    outer->addWidget(m_legendBar);

    drawBackground();
    m_view->fitInView(m_scene->sceneRect(), Qt::KeepAspectRatio);
}

// ================================================================
// drawBackground — hand-drawn dark world map
// ================================================================
void RouteMapWidget::drawBackground()
{
    QPen grid(QColor(255, 255, 255, 12), 0.5);
    for (int lat = -60; lat <= 60; lat += 30) {
        QPointF a = geo2scene(lat, -180), b = geo2scene(lat, 180);
        m_scene->addLine(a.x(), a.y(), b.x(), b.y(), grid)->setZValue(0);
    }
    for (int lon = -150; lon <= 180; lon += 30) {
        QPointF a = geo2scene(90, lon), b = geo2scene(-90, lon);
        m_scene->addLine(a.x(), a.y(), b.x(), b.y(), grid)->setZValue(0);
    }

    QColor lc(38, 52, 68, 220);
    QPen   lp(QColor(55, 75, 95, 100), 0.5);
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
}

// ================================================================
// rebuildLegend
// ================================================================
void RouteMapWidget::rebuildLegend()
{
    // clear old widgets
    if (auto *old = m_legendBar->layout()) {
        while (auto *it = old->takeAt(0)) {
            if (it->widget()) it->widget()->deleteLater();
            delete it;
        }
        delete old;
    }

    auto *lay = new QHBoxLayout(m_legendBar);
    lay->setContentsMargins(16, 0, 16, 0);
    lay->setSpacing(0);

    for (int i = 0; i < m_connItems.size(); ++i) {
        const ConnItem &ci = m_connItems[i];

        auto *entry = new QWidget(m_legendBar);
        entry->setObjectName("LegendEntry");
        entry->setProperty("ipkey", ci.ip);
        entry->setCursor(Qt::PointingHandCursor);
        if (ci.ip == m_selIp)
            entry->setStyleSheet(
                "background:#1a2a3a;border-radius:6px;");

        auto *el = new QVBoxLayout(entry);
        el->setContentsMargins(10, 6, 10, 6);
        el->setSpacing(2);

        auto *top = new QHBoxLayout();
        top->setSpacing(7);

        auto *dot = new QLabel(entry);
        dot->setFixedSize(10, 10);
        dot->setStyleSheet(
            QString("background:%1;border-radius:5px;")
                .arg(ci.color.name()));

        auto *nm = new QLabel(ci.label, entry);
        nm->setStyleSheet(
            QString("color:%1;font-size:13px;font-weight:600;"
                    "font-family:'Ubuntu Mono';")
                .arg(ci.ready ? ci.color.name() : "#484f58"));

        top->addWidget(dot);
        top->addWidget(nm);
        el->addLayout(top);

        auto *sub = new QLabel(
            QString("%1  %2").arg(ci.rate, ci.proto), entry);
        sub->setStyleSheet(
            "color:#484f58;font-size:10px;font-family:'Ubuntu Mono';");
        el->addWidget(sub);

        entry->installEventFilter(this);
        lay->addWidget(entry);

        if (i < m_connItems.size() - 1) {
            auto *sep = new QFrame(m_legendBar);
            sep->setFrameShape(QFrame::VLine);
            sep->setStyleSheet("background:#30363d;max-width:1px;");
            sep->setFixedHeight(38);
            lay->addWidget(sep);
        }
    }

    lay->addStretch();

    // RTT legend
    auto *sep = new QFrame(m_legendBar);
    sep->setFrameShape(QFrame::VLine);
    sep->setStyleSheet("background:#30363d;max-width:1px;");
    sep->setFixedHeight(38);
    lay->addWidget(sep);

    struct RttEntry { QString label; QString color; };
    QList<RttEntry> rtts = {
        {"fast <50ms",        "#3fb950"},
        {"medium <150ms",     "#d29922"},
        {"slow >150ms",       "#f85149"},
        {"travelling packet", "#ffffff"},
    };
    for (const auto &r : rtts) {
        auto *w  = new QWidget(m_legendBar);
        auto *wl = new QHBoxLayout(w);
        wl->setContentsMargins(10, 0, 6, 0);
        wl->setSpacing(7);
        auto *d = new QLabel(w);
        d->setFixedSize(10, 10);
        d->setStyleSheet(
            QString("background:%1;border-radius:5px;").arg(r.color));
        auto *t = new QLabel(r.label, w);
        t->setStyleSheet(
            "color:#8b949e;font-size:11px;font-family:'Ubuntu Mono';");
        wl->addWidget(d);
        wl->addWidget(t);
        lay->addWidget(w);
    }
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
// redrawRoutes
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

        // valid geo hops
        QVector<QPointF>         pts;
        QVector<const RouteHop*> hops;
        for (const auto &h : re.hops) {
            if (!h.hasGeo()) continue;
            if (qAbs(h.lat) < 0.1 && qAbs(h.lon) < 0.1) continue;
            pts.append(geo2scene(h.lat, h.lon));
            hops.append(&h);
        }
        if (pts.size() < 2) continue;

        // arcs
        for (int i = 0; i + 1 < pts.size(); ++i) {
            QPointF p1 = pts[i], p2 = pts[i + 1];
            QPointF mid = (p1 + p2) / 2.0;
            mid.setY(mid.y() - QLineF(p1, p2).length() * 0.18);

            QPainterPath path;
            path.moveTo(p1);
            path.quadTo(mid, p2);

            QColor lc = active ? col : col.darker(280);
            QPen pen(lc, active ? 2.5 : 0.7);
            if (!active) pen.setStyle(Qt::DashLine);

            auto *arc = m_scene->addPath(path, pen);
            arc->setOpacity(active ? 1.0 : 0.2);
            arc->setZValue(10);
            m_routeItems.append(arc);

            // distance label on active arc
            if (active && i + 1 < (int)hops.size()) {
                double km = haversine(hops[i]->lat, hops[i]->lon,
                                      hops[i+1]->lat, hops[i+1]->lon);
                if (km > 200) {
                    QString s = km > 999 ?
                        QString("%1K km").arg(int(km / 1000)) :
                        QString("%1 km").arg(int(km));
                    auto *t = m_scene->addText(s);
                    t->setDefaultTextColor(QColor("#4a5568"));
                    t->setFont(QFont("Ubuntu Mono", 7));
                    t->setPos(mid.x() - 22, mid.y() - 18);
                    t->setZValue(12);
                    m_routeItems.append(t);
                }
            }
        }

        // hop dots
        for (int i = 0; i < (int)hops.size(); ++i) {
            const RouteHop *h = hops[i];
            QPointF pt = pts[i];
            bool first = (i == 0), last = (i == (int)hops.size() - 1);
            double r = (first || last) ? 6.5 : 4.0;
            QColor dc = active ? QColor(h->rttColorHex())
                               : col.darker(300);

            if (active) {
                auto *g = m_scene->addEllipse(
                    pt.x()-r*2.2, pt.y()-r*2.2, r*4.4, r*4.4,
                    QPen(Qt::NoPen),
                    QBrush(QColor(dc.red(), dc.green(), dc.blue(), 35)));
                g->setZValue(9);
                m_routeItems.append(g);
            }

            auto *dot = m_scene->addEllipse(
                pt.x()-r, pt.y()-r, r*2, r*2,
                QPen(QColor(255, 255, 255, active ? 80 : 15), 0.8),
                QBrush(active ? dc : dc.darker(200)));
            dot->setZValue(11);
            m_routeItems.append(dot);

            // label
            if (active) {
                bool hasCity = !h->city.isEmpty() &&
                               h->city != "-" && h->city != "0";
                if (first || last || hasCity) {
                    QString city = first ? "you" :
                        (hasCity ? h->city : "");
                    if (city.isEmpty()) continue;
                    QString rttS = first ? "" :
                        QString("  %1ms").arg(int(h->rttMs));
                    auto *lbl = m_scene->addText(city + rttS);
                    lbl->setDefaultTextColor(first ? col : QColor("#8b949e"));
                    lbl->setFont(QFont("Ubuntu Mono", 8));
                    double lx = qBound(
                        2.0,
                        pt.x() - lbl->boundingRect().width() / 2.0,
                        SW - lbl->boundingRect().width() - 2.0);
                    lbl->setPos(lx, pt.y() - r - 20);
                    lbl->setZValue(13);
                    m_routeItems.append(lbl);
                }
            }
        }

        // animated dot
        if (pts.size() >= 2) {
            auto *cd = new ConnDot(pts, col, active, m_scene);
            cd->setZValue(20);
            cd->start();
            m_dots.append(cd);
            m_routeItems.append(cd);
        }
    }

    // fit view
    if (!m_selIp.isEmpty() && m_routes.contains(m_selIp) &&
        m_routes[m_selIp].isReady()) {
        QRectF bbox;
        for (const auto &h : m_routes[m_selIp].hops) {
            if (!h.hasGeo()) continue;
            if (qAbs(h.lat) < 0.1 && qAbs(h.lon) < 0.1) continue;
            QPointF pt = geo2scene(h.lat, h.lon);
            if (bbox.isNull()) bbox = QRectF(pt, QSizeF(1, 1));
            else bbox = bbox.united(QRectF(pt, QSizeF(1, 1)));
        }
        if (!bbox.isNull()) {
            bbox.adjust(-80, -50, 80, 50);
            m_view->fitInView(bbox, Qt::KeepAspectRatio);
        }
    } else {
        m_view->fitInView(m_scene->sceneRect(), Qt::KeepAspectRatio);
    }
}

// ================================================================
// updateInfoPanels
// ================================================================
void RouteMapWidget::updateInfoPanels(const QString &ip)
{
    if (!m_routes.contains(ip) || !m_routes[ip].isReady()) {
        m_sovereignty->setText("Route pending...");
        m_latency->setText("Route pending...");
        return;
    }
    const RouteEntry &re = m_routes[ip];

    QStringList countries;
    QSet<QString> sc;
    for (const auto &h : re.hops)
        if (!h.country.isEmpty() && h.country != "-" &&
            !sc.contains(h.cc)) {
            sc.insert(h.cc);
            countries << h.country;
        }
    m_sovereignty->setText(countries.isEmpty()
        ? "No geo data" : countries.join(" -> "));

    double worst = 0; int wi = -1;
    for (int i = 1; i < re.hops.size(); ++i) {
        double d = re.hops[i].rttMs - re.hops[i-1].rttMs;
        if (d > worst) { worst = d; wi = i; }
    }
    if (wi > 0) {
        const RouteHop &f = re.hops[wi-1], &t = re.hops[wi];
        double total = re.hops.last().rttMs;
        int pct = total > 0 ? int(worst / total * 100) : 0;
        QString fc = f.city.isEmpty() || f.city == "-" ? f.hopIp : f.city;
        QString tc = t.city.isEmpty() || t.city == "-" ? t.hopIp : t.city;
        double km = (f.hasGeo() && t.hasGeo()) ?
            haversine(f.lat, f.lon, t.lat, t.lon) : 0;
        m_latency->setText(
            QString("Slowest:\n%1 -> %2\n+%3ms (%4%%)%5")
                .arg(fc, tc)
                .arg(worst, 0, 'f', 1)
                .arg(pct)
                .arg(km > 0 ? QString("\n%1 km").arg(int(km)) : ""));
    } else {
        m_latency->setText("Insufficient data");
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
