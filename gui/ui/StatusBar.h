#pragma once

#include <QWidget>
#include "../core/ProcReader.h"

class QLabel;
class QTimer;

class StatusBar : public QWidget
{
    Q_OBJECT
public:
    explicit StatusBar(QWidget *parent = nullptr);
    void updateSnapshot(const ProcSnapshot &snap);

protected:
    void paintEvent(QPaintEvent *event) override;

private:
    QLabel *m_connections = nullptr;
    QLabel *m_active = nullptr;
    QLabel *m_processes = nullptr;
    QLabel *m_anomalies = nullptr;
    QLabel *m_time = nullptr;
    QTimer *m_clock = nullptr;
};
