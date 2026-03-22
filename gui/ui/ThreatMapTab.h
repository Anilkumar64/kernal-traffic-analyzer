#pragma once
#include <QWidget>
#include <QGraphicsView>
#include <QGraphicsScene>
#include <QTableWidget>
#include <QLabel>
#include <QTimer>
#include "../core/TrafficEntry.h"
#include "../core/ThreatIntel.h"

class ThreatMapTab : public QWidget
{
    Q_OBJECT
public:
    explicit ThreatMapTab(QWidget *parent = nullptr);
    void updateData(const QVector<TrafficEntry> &conns);

private:
    void rebuildMap();
    void rebuildTable();
    QPointF geo2scene(double lat, double lon) const;
    void drawBackground();

    QGraphicsView *m_view;
    QGraphicsScene *m_scene;
    QTableWidget *m_table;
    QLabel *m_statusLabel;

    QVector<TrafficEntry> m_conns;
    QList<QGraphicsItem *> m_items;

    static constexpr double SW = 900.0;
    static constexpr double SH = 420.0;
};