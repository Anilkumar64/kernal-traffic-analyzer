#include "AlertPopup.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QPropertyAnimation>
#include <QGraphicsOpacityEffect>
#include <QPainter>
#include <QPainterPath>
#include <QApplication>
#include <QScreen>

AlertPopup::AlertPopup(QWidget *parent) : QWidget(parent,
    Qt::Tool | Qt::FramelessWindowHint | Qt::WindowStaysOnTopHint)
{
    setAttribute(Qt::WA_TranslucentBackground);
    setAttribute(Qt::WA_ShowWithoutActivating);
    setFixedSize(W, H);

    auto *root = new QWidget(this);
    root->setGeometry(0, 0, W, H);
    root->setStyleSheet(
        "QWidget {"
        "  background-color: #f7f8fa;"
        "  border: 1px solid #ef4444;"
        "  border-radius: 12px;"
        "  font-family: 'Ubuntu Mono';"
        "}");

    auto *lay = new QHBoxLayout(root);
    lay->setContentsMargins(14, 12, 14, 12);
    lay->setSpacing(12);

    // Icon
    m_icon = new QLabel("⚠", root);
    m_icon->setFixedSize(36, 36);
    m_icon->setAlignment(Qt::AlignCenter);
    m_icon->setStyleSheet(
        "color:#ef4444;font-size:20px;"
        "background:#2a1010;border-radius:8px;"
        "border:none;");
    lay->addWidget(m_icon);

    // Text column
    auto *textCol = new QVBoxLayout();
    textCol->setSpacing(3);

    m_title = new QLabel(root);
    m_title->setStyleSheet(
        "color:#ef4444;font-size:13px;font-weight:700;"
        "border:none;background:transparent;");

    m_body = new QLabel(root);
    m_body->setStyleSheet(
        "color:#1e2a3a;font-size:13px;"
        "border:none;background:transparent;");

    m_sub = new QLabel(root);
    m_sub->setStyleSheet(
        "color:#5c6b7f;font-size:11px;"
        "border:none;background:transparent;");

    textCol->addWidget(m_title);
    textCol->addWidget(m_body);
    textCol->addWidget(m_sub);
    lay->addLayout(textCol, 1);

    // Auto-close timer
    m_autoClose = new QTimer(this);
    m_autoClose->setSingleShot(true);
    connect(m_autoClose, &QTimer::timeout, this, &AlertPopup::dismiss);

    hide();
}

void AlertPopup::showAlert(const AnomalyEntry &a)
{
    QString typeColor = "#ef4444";
    QString icon = "⚠";

    if (a.anomaly == "PORT_SCAN") {
        typeColor = "#ef4444"; icon = "⚡";
        m_title->setText("PORT SCAN DETECTED");
    } else if (a.anomaly == "SYN_FLOOD") {
        typeColor = "#ff6060"; icon = "💥";
        m_title->setText("SYN FLOOD DETECTED");
    } else if (a.anomaly == "CONN_BURST") {
        typeColor = "#f59e0b"; icon = "⚡";
        m_title->setText("CONNECTION BURST");
    } else if (a.anomaly == "HIGH_BW") {
        typeColor = "#f59e0b"; icon = "📡";
        m_title->setText("HIGH BANDWIDTH");
    } else {
        m_title->setText(a.anomaly);
    }

    m_icon->setText(icon);
    m_icon->setStyleSheet(
        QString("color:%1;font-size:20px;"
                "background:#2a1010;border-radius:8px;"
                "border:none;").arg(typeColor));
    m_title->setStyleSheet(
        QString("color:%1;font-size:13px;font-weight:700;"
                "border:none;background:transparent;")
            .arg(typeColor));

    m_body->setText(QString("%1  (PID %2)")
        .arg(a.process).arg(a.pid));
    m_sub->setText(
        QString("conns/s: %1  |  ports: %2  |  %3  %4")
            .arg(a.newConnsLastSec)
            .arg(a.uniquePortsLastSec)
            .arg(a.formatRate(a.rateOutBps))
            .arg(a.formatRate(a.rateInBps)));

    animateIn();
    m_autoClose->start(8000);
}

void AlertPopup::showBgpAlert(const QString &domain,
                               const QString &expected,
                               const QString &current)
{
    m_icon->setText("🔀");
    m_title->setText("BGP ROUTE CHANGED");
    m_body->setText(domain);
    m_sub->setText(QString("%1 → %2").arg(expected, current));

    m_icon->setStyleSheet(
        "color:#f59e0b;font-size:20px;"
        "background:#fffbeb;border-radius:8px;border:none;");
    m_title->setStyleSheet(
        "color:#f59e0b;font-size:13px;font-weight:700;"
        "border:none;background:transparent;");

    animateIn();
    m_autoClose->start(10000);
}

void AlertPopup::animateIn()
{
    positionSelf();
    setWindowOpacity(0.0);
    show();
    raise();

    auto *anim = new QPropertyAnimation(this, "opacity", this);
    anim->setDuration(200);
    anim->setStartValue(0.0);
    anim->setEndValue(1.0);
    anim->start(QAbstractAnimation::DeleteWhenStopped);
    m_visible = true;
}

void AlertPopup::animateOut()
{
    auto *anim = new QPropertyAnimation(this, "opacity", this);
    anim->setDuration(300);
    anim->setStartValue(windowOpacity());
    anim->setEndValue(0.0);
    connect(anim, &QPropertyAnimation::finished, this, &QWidget::hide);
    anim->start(QAbstractAnimation::DeleteWhenStopped);
    m_visible = false;
}

void AlertPopup::dismiss()
{
    m_autoClose->stop();
    animateOut();
}

void AlertPopup::positionSelf()
{
    QWidget *p = parentWidget();
    QRect pr = p ? p->geometry() :
        QApplication::primaryScreen()->geometry();

    // Bottom-right corner with 16px margin
    move(pr.right() - W - 16,
         pr.bottom() - H - 48); // 48 = above status bar
}

void AlertPopup::paintEvent(QPaintEvent *)
{
    // Transparent — child QWidget handles background
}
