#pragma once
#include <QWidget>
#include <QLabel>
#include <QTableWidget>
#include <QGraphicsView>
#include <QGraphicsScene>
#include <QPushButton>
#include <QScrollArea>
#include "../core/ProcEntry.h"
#include "../core/TrafficEntry.h"
#include "../core/DnsEntry.h"
#include "../core/RouteEntry.h"

// 5-minute bandwidth graph
class ProcBwGraph : public QWidget
{
    Q_OBJECT
public:
    explicit ProcBwGraph(QWidget *parent = nullptr);
    void addSample(quint32 out, quint32 in);
    void clear();
protected:
    void paintEvent(QPaintEvent *) override;
private:
    static constexpr int MAX = 300;
    QVector<quint32> m_out, m_in;
    quint32 m_peak = 1;
    QString fmtRate(quint32 bps) const;
};

// Full-screen process detail overlay
class ProcessDetailOverlay : public QWidget
{
    Q_OBJECT
public:
    explicit ProcessDetailOverlay(QWidget *parent = nullptr);

    void showProcess(const QString &process,
                     const QVector<ProcEntry> &procs,
                     const QVector<TrafficEntry> &conns,
                     const QVector<DnsEntry> &dns,
                     const QMap<QString, RouteEntry> &routes);
    void hide();
    QString currentProcess() const { return m_process; }

signals:
    void closed();

protected:
    void paintEvent(QPaintEvent *) override;
    void keyPressEvent(QKeyEvent *) override;
    void resizeEvent(QResizeEvent *) override;

private:
    void buildLayout();
    void populateInfo(const ProcEntry &proc);
    void populateConnections(const QVector<TrafficEntry> &conns);
    void populateDns(const QVector<DnsEntry> &dns);
    void drawMiniMap(const QVector<TrafficEntry> &conns,
                     const QMap<QString, RouteEntry> &routes);
    QPointF geo2scene(double lat, double lon) const;
    void repositionCard();

    // Header
    QLabel *m_procName;
    QLabel *m_exePath;
    QLabel *m_pidLabel;

    // Stat cards
    QLabel *m_cardConns;
    QLabel *m_cardOut;
    QLabel *m_cardIn;
    QLabel *m_cardTotal;
    QLabel *m_cardAnomaly;

    // Graph
    ProcBwGraph *m_graph;

    // Tables
    QTableWidget *m_connTable;
    QTableWidget *m_dnsTable;

    // Mini map
    QGraphicsView  *m_mapView;
    QGraphicsScene *m_mapScene;

    // Card container
    QWidget    *m_card;
    QScrollArea *m_scroll;

    QString m_process;
    int     m_pid = 0;

    static constexpr double MW = 540.0;
    static constexpr double MH = 240.0;
};
