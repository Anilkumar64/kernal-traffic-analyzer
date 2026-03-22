#pragma once
#include <QPainter>
#include <QRect>
#include <QObject>
#include <QString>
#include "../core/ProcReader.h"
#include "../core/CostTracker.h"

class Exporter : public QObject
{
    Q_OBJECT
public:
    explicit Exporter(QObject *parent = nullptr);

    bool exportJson(const QString &path, const ProcSnapshot &snap);
    bool exportCsv (const QString &path, const QVector<TrafficEntry> &conns);
    bool exportPdf (const QString &path, const ProcSnapshot &snap);

private:
    // PDF helpers
    void drawPageHeader(QPainter &p, const QRect &pageRect,
                        const QString &title, int pageNum, int totalPages);
    void drawTable(QPainter &p, QRect &cursor,
                   const QStringList &headers,
                   const QVector<QStringList> &rows,
                   const QVector<QColor> &rowColors = {});
    QRect pageRect() const;

    static constexpr int MARGIN = 60;
};
