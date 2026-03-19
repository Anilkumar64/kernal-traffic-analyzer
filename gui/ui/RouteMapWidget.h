#pragma once
#include <QWidget>
#include <QGraphicsView>
#include <QGraphicsScene>
#include <QGraphicsEllipseItem>
#include <QLabel>
#include <QTimer>
#include <QMap>
#include <QList>
#include <QSet>
#include <QEvent>
#include <QGraphicsItem>
#include "../core/RouteEntry.h"
#include "../core/TrafficEntry.h"

// ── animated packet dot ──────────────────────────────────────────
class ConnDot : public QObject, public QGraphicsEllipseItem
{
    Q_OBJECT
public:
    ConnDot(const QVector<QPointF> &pts,
            const QColor &color,
            bool large,
            QGraphicsScene *scene);
    void start();
    void stop();
private slots:
    void tick();
private:
    QVector<QPointF> m_pts;
    int    m_seg   = 0;
    double m_t     = 0.0;
    double m_speed = 0.008;
    QTimer *m_timer = nullptr;
};

// ── main widget ──────────────────────────────────────────────────
class RouteMapWidget : public QWidget
{
    Q_OBJECT
public:
    explicit RouteMapWidget(QWidget *parent = nullptr);
    void updateRoutes(const QMap<QString, RouteEntry> &routes,
                      const QVector<TrafficEntry> &connections);

protected:
    bool eventFilter(QObject *obj, QEvent *ev) override;

private:
    // build
    void buildLayout();
    void drawBackground();

    // data
    void rebuildList();

    // drawing
    void redrawRoutes();
    void clearRouteItems();

    // selection
    void selectIp(const QString &ip);
    void updateInfoPanels(const QString &ip);

    // legend
    void rebuildLegend();

    // helpers
    QPointF geo2scene(double lat, double lon) const;
    double  haversine(double la1, double lo1,
                      double la2, double lo2) const;
    QColor  connColor(int idx) const;

    // ── widgets ──
    QGraphicsView  *m_view      = nullptr;
    QGraphicsScene *m_scene     = nullptr;
    QWidget        *m_legendBar = nullptr;
    QWidget        *m_leftPanel = nullptr;
    QLabel         *m_sovereignty = nullptr;
    QLabel         *m_latency     = nullptr;

    // ── state ──
    QString m_selIp;
    QMap<QString, RouteEntry> m_routes;
    QVector<TrafficEntry>     m_conns;

    // ── drawing items ──
    QList<ConnDot*>       m_dots;
    QList<QGraphicsItem*> m_routeItems;

    // ── connection list ──
    struct ConnItem {
        QString ip;
        QString label;
        QString rate;
        QString proto;
        QColor  color;
        bool    ready = false;
    };
    QVector<ConnItem> m_connItems;

    // ── constants ──
    static constexpr double SW = 1080.0;
    static constexpr double SH = 500.0;
    static const QStringList COLORS;
};
