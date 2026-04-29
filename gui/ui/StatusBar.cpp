#include "StatusBar.h"
#include "Style.h"

#include <QDateTime>
#include <QGraphicsOpacityEffect>
#include <QHBoxLayout>
#include <QLabel>
#include <QPainter>
#include <QPropertyAnimation>
#include <QTimer>

class StatusPulseDot : public QWidget
{
public:
    explicit StatusPulseDot(QWidget *parent = nullptr) : QWidget(parent)
    {
        setFixedSize(6, 6);
        auto *effect = new QGraphicsOpacityEffect(this);
        setGraphicsEffect(effect);
        auto *anim = new QPropertyAnimation(effect, "opacity", this);
        anim->setStartValue(1.0);
        anim->setKeyValueAt(0.5, 0.4);
        anim->setEndValue(1.0);
        anim->setDuration(2000);
        anim->setLoopCount(-1);
        anim->start();
    }
protected:
    void paintEvent(QPaintEvent *) override
    {
        QPainter p(this);
        p.setRenderHint(QPainter::Antialiasing);
        p.setPen(Qt::NoPen);
        p.setBrush(KtaColors::StatusDot);
        p.drawEllipse(rect());
    }
};

static QLabel *statusLabel(const QString &text, QWidget *parent)
{
    auto *label = new QLabel(text, parent);
    label->setFont(uiFont(11));
    label->setStyleSheet("color:rgba(255,255,255,0.85);background:transparent;");
    return label;
}

static QWidget *separator(QWidget *parent)
{
    auto *line = new QWidget(parent);
    line->setFixedSize(1, 14);
    line->setStyleSheet("background:rgba(255,255,255,0.20);");
    return line;
}

StatusBar::StatusBar(QWidget *parent) : QWidget(parent)
{
    setFixedHeight(24);
    auto *layout = new QHBoxLayout(this);
    layout->setContentsMargins(16, 0, 16, 0);
    layout->setSpacing(10);
    layout->addWidget(new StatusPulseDot(this));
    m_connections = statusLabel("0 connections", this);
    m_active = statusLabel("0 active", this);
    m_processes = statusLabel("0 processes", this);
    m_anomalies = statusLabel("0 anomalies", this);
    m_time = statusLabel(QTime::currentTime().toString("hh:mm:ss"), this);
    m_time->setFont(monoFont(11));
    layout->addWidget(m_connections);
    layout->addWidget(separator(this));
    layout->addWidget(m_active);
    layout->addWidget(separator(this));
    layout->addWidget(m_processes);
    layout->addWidget(separator(this));
    layout->addWidget(m_anomalies);
    layout->addStretch();
    layout->addWidget(m_time);

    m_clock = new QTimer(this);
    connect(m_clock, &QTimer::timeout, this, [this] { m_time->setText(QTime::currentTime().toString("hh:mm:ss")); });
    m_clock->start(1000);
}

void StatusBar::updateSnapshot(const ProcSnapshot &snap)
{
    const auto active = std::count_if(snap.connections.begin(), snap.connections.end(), [](const TrafficEntry &e) { return e.isActive(); });
    m_connections->setText(QString("%1 connections").arg(snap.connections.size()));
    m_active->setText(QString("%1 active").arg(active));
    m_processes->setText(QString("%1 processes").arg(snap.processes.size()));
    m_anomalies->setText(QString("%1 anomalies").arg(snap.anomalyCount()));
}

void StatusBar::paintEvent(QPaintEvent *)
{
    QPainter p(this);
    p.fillRect(rect(), KtaColors::StatusBar);
}
