#pragma once
#include <QWidget>
#include <QLabel>
#include <QTimer>
#include <QVector>
#include <QProcess>

struct PingResult
{
    qint64 ts = 0;
    double latency = 0.0; // ms, -1 = timeout
    bool ok = false;
};

class LatencyGraph : public QWidget
{
    Q_OBJECT
public:
    explicit LatencyGraph(QWidget *parent = nullptr);
    void addSample(double latencyMs, bool ok);
    void clear();
    double avgLatency() const;
    double packetLoss() const;

protected:
    void paintEvent(QPaintEvent *) override;

private:
    static constexpr int MAX = 120;
    QVector<PingResult> m_samples;
};

class NetworkPerfTab : public QWidget
{
    Q_OBJECT
public:
    explicit NetworkPerfTab(QWidget *parent = nullptr);

private slots:
    void onPingResult(int exitCode, QProcess::ExitStatus);
    void startPing();

private:
    void updateCards();

    QLabel *m_latencyCard;
    QLabel *m_lossCard;
    QLabel *m_jitterCard;
    QLabel *m_qualityCard;
    QLabel *m_statusLabel;
    LatencyGraph *m_graph;
    QProcess *m_pingProc = nullptr;
    QTimer *m_timer;

    QVector<double> m_latencies;
    int m_sent = 0;
    int m_recv = 0;
    QString m_target = "8.8.8.8";
};