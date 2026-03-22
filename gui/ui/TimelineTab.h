#pragma once
#include <QWidget>
#include <QScrollArea>
#include <QComboBox>
#include <QLabel>
#include <QTimer>
#include <QMap>
#include "../core/TrafficEntry.h"

struct TimelineEntry {
    QString process;
    QString domain;
    QString destIp;
    int     destPort  = 0;
    QString protocol;
    QString state;
    qint64  firstSeen = 0;
    qint64  lastSeen  = 0;
    bool    isActive  = false;
    quint64 bytes     = 0;
};

class TimelineCanvas : public QWidget
{
    Q_OBJECT
public:
    explicit TimelineCanvas(QWidget *parent = nullptr);
    void setEntries(const QVector<TimelineEntry> &entries,
                    const QString &filter);

protected:
    void paintEvent(QPaintEvent *) override;
    void mousePressEvent(QMouseEvent *) override;
    void mouseMoveEvent(QMouseEvent *) override;

private:
    QVector<TimelineEntry> m_entries;
    QString m_filter;
    int     m_hoverRow = -1;
    static constexpr int ROW_H  = 28;
    static constexpr int LABEL_W = 200;
    static constexpr int WINDOW_SECS = 1800; // 30 min
};

class TimelineTab : public QWidget
{
    Q_OBJECT
public:
    explicit TimelineTab(QWidget *parent = nullptr);
    void updateData(const QVector<TrafficEntry> &entries);

private:
    void rebuild();

    QComboBox     *m_filter;
    QLabel        *m_countLabel;
    TimelineCanvas *m_canvas;
    QScrollArea   *m_scroll;
    QTimer        *m_pulseTimer;

    // Keep history of connections
    QMap<QString, TimelineEntry> m_history; // key = src:srcPort-dst:dstPort
};
