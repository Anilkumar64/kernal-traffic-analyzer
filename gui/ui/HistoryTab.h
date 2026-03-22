#pragma once
#include <QWidget>
#include <QListWidget>
#include <QLabel>
#include <QTimer>
#include "../core/HistoryDB.h"

class BwGraph : public QWidget
{
    Q_OBJECT
public:
    enum Mode { Hour, Day24, Week };
    explicit BwGraph(const QString &title, Mode mode, QWidget *parent=nullptr);
    void setProcess(const QString &process);
    void refresh();

protected:
    void paintEvent(QPaintEvent *) override;

private:
    void drawGraph(QPainter &p, const QRect &r,
                   const QVector<BwSample> &samples,
                   const QVector<QString> &labels);
    void drawBarChart(QPainter &p, const QRect &r,
                      const QVector<DailyTotal> &totals);
    QString formatRate(quint32 bps) const;
    QString formatBytes(quint64 b) const;

    QString m_title;
    Mode    m_mode;
    QString m_process;
    QVector<BwSample>   m_samples;
    QVector<DailyTotal> m_totals;
};

class HistoryTab : public QWidget
{
    Q_OBJECT
public:
    explicit HistoryTab(QWidget *parent = nullptr);
    void refresh();

private slots:
    void onProcessSelected(QListWidgetItem *item);

private:
    void rebuildProcessList();

    QListWidget *m_procList;
    BwGraph     *m_hourGraph;
    BwGraph     *m_dayGraph;
    BwGraph     *m_weekGraph;
    QTimer      *m_refreshTimer;
    QString      m_selectedProcess;
};
