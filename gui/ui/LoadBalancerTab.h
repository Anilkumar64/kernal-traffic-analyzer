#pragma once
#include <QWidget>
#include <QScrollArea>
#include <QLabel>
#include <QMap>
#include "../core/TrafficEntry.h"
#include "../core/ProcEntry.h"

class ProcessLoadBar : public QWidget
{
    Q_OBJECT
public:
    explicit ProcessLoadBar(QWidget *parent = nullptr);
    void setData(const QString &process,
                 const QString &exe,
                 quint32 rateOut,
                 quint32 rateIn,
                 quint64 totalBytes,
                 int connections,
                 quint32 peakOut,
                 quint32 peakIn,
                 const QString &anomaly);

signals:
    void clicked(const QString &process);

protected:
    void paintEvent(QPaintEvent *) override;
    void mousePressEvent(QMouseEvent *) override;

private:
    QString m_process;
    QString m_exe;
    quint32 m_rateOut    = 0;
    quint32 m_rateIn     = 0;
    quint64 m_totalBytes = 0;
    int     m_conns      = 0;
    quint32 m_peakOut    = 1;
    quint32 m_peakIn     = 1;
    QString m_anomaly;

    QString fmtRate(quint32 bps) const;
    QString fmtBytes(quint64 b) const;
};

class LoadBalancerTab : public QWidget
{
    Q_OBJECT
public:
    explicit LoadBalancerTab(QWidget *parent = nullptr);
    void updateData(const QVector<ProcEntry> &procs,
                    const QVector<TrafficEntry> &conns);

signals:
    void processSelected(const QString &process);

private:
    void rebuild();

    QLabel      *m_totalLabel;
    QScrollArea *m_scroll;
    QWidget     *m_container;

    QVector<ProcEntry>    m_procs;
    QVector<TrafficEntry> m_conns;
    QMap<QString, quint32> m_peakOut;
    QMap<QString, quint32> m_peakIn;
};
