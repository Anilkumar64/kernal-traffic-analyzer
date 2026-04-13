#include "TrayIcon.h"
#include <QPainter>
#include <QPixmap>
#include <QPainterPath>

TrayIcon::TrayIcon(QWidget *parent)
    : QSystemTrayIcon(parent)
{
    m_menu = new QMenu();
    m_menu->setStyleSheet(
        "QMenu{background:#f7f8fa;border:1px solid #d0d7e0;"
        "color:#1e2a3a;font-family:'Ubuntu Mono';font-size:13px;}"
        "QMenu::item{padding:6px 20px;}"
        "QMenu::item:selected{background:#e0ecff;color:#6366f1;}"
        "QMenu::separator{background:#e4e8ee;height:1px;margin:4px 0;}");

    m_showAction = m_menu->addAction("Show KTA");
    m_menu->addSeparator();
    m_connAction = m_menu->addAction("Connections: 0");
    m_connAction->setEnabled(false);
    m_anomalyAction = m_menu->addAction("Anomalies: 0");
    m_anomalyAction->setEnabled(false);
    m_menu->addSeparator();
    auto *quit = m_menu->addAction("Quit");

    setContextMenu(m_menu);

    connect(m_showAction, &QAction::triggered,
            this, &TrayIcon::showRequested);
    connect(quit, &QAction::triggered,
            this, &TrayIcon::quitRequested);
    connect(this, &QSystemTrayIcon::activated,
            this, [this](QSystemTrayIcon::ActivationReason r)
            {
                if (r == QSystemTrayIcon::DoubleClick)
                    emit showRequested(); });

    setIcon(makeIcon(0, 0));
    setToolTip("KTA — Kernel Traffic Analyzer");
    show();
}

QIcon TrayIcon::makeIcon(int anomalies, quint32 rateBps) const
{
    QPixmap pm(22, 22);
    pm.fill(Qt::transparent);
    QPainter p(&pm);
    p.setRenderHint(QPainter::Antialiasing);

    // Hexagon
    QColor hexColor = anomalies > 0 ? QColor("#ef4444") : rateBps > 0 ? QColor("#6366f1")
                                                                      : QColor("#d0d7e0");

    QPainterPath hex;
    QPointF center(11, 11);
    double r = 9.0;
    for (int i = 0; i < 6; ++i)
    {
        double angle = M_PI / 6.0 + i * M_PI / 3.0;
        QPointF pt(center.x() + r * qCos(angle),
                   center.y() + r * qSin(angle));
        if (i == 0)
            hex.moveTo(pt);
        else
            hex.lineTo(pt);
    }
    hex.closeSubpath();

    p.setPen(QPen(hexColor, 1.5));
    if (anomalies > 0)
        p.setBrush(QColor(240, 64, 64, 60));
    else
        p.setBrush(Qt::NoBrush);
    p.drawPath(hex);

    // Inner dot
    p.setPen(Qt::NoPen);
    p.setBrush(hexColor);
    p.drawEllipse(center, 3.0, 3.0);

    // Anomaly badge
    if (anomalies > 0)
    {
        p.setBrush(QColor("#ef4444"));
        p.setPen(Qt::NoPen);
        p.drawEllipse(QPointF(17, 5), 5, 5);
        QFont f("Arial");
        f.setPixelSize(7);
        f.setWeight(QFont::Bold);
        p.setFont(f);
        p.setPen(Qt::white);
        p.drawText(QRect(12, 1, 10, 8), Qt::AlignCenter,
                   anomalies < 10 ? QString::number(anomalies) : "9+");
    }

    return QIcon(pm);
}

void TrayIcon::update(int connections, int anomalies, quint32 totalRateBps)
{
    m_lastConnections = connections;
    m_lastAnomalies = anomalies;

    setIcon(makeIcon(anomalies, totalRateBps));

    m_connAction->setText(
        QString("Connections: %1").arg(connections));
    m_anomalyAction->setText(
        QString("Anomalies: %1").arg(anomalies));

    QString tip = QString("KTA — %1 connections").arg(connections);
    if (anomalies > 0)
        tip += QString(", %1 anomal%2")
                   .arg(anomalies)
                   .arg(anomalies == 1 ? "y" : "ies");
    setToolTip(tip);
}