#pragma once
#include <QSystemTrayIcon>
#include <QMenu>
#include <QAction>

class TrayIcon : public QSystemTrayIcon
{
    Q_OBJECT
public:
    explicit TrayIcon(QWidget *parent = nullptr);
    void update(int connections, int anomalies, quint32 totalRateBps);

signals:
    void showRequested();
    void quitRequested();

private:
    QIcon makeIcon(int anomalies, quint32 rateBps) const;

    QAction *m_showAction;
    QAction *m_connAction;
    QAction *m_anomalyAction;
    QMenu   *m_menu;

    int     m_lastConnections = 0;
    int     m_lastAnomalies   = 0;
};
