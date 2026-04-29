#include "StatCard.h"
#include "Style.h"

#include <QLabel>
#include <QPainter>
#include <QVBoxLayout>

StatCard::StatCard(const QString &label, const QColor &valueColor, QWidget *parent) : QWidget(parent)
{
    setMinimumHeight(98);
    auto *layout = new QVBoxLayout(this);
    layout->setContentsMargins(18, 14, 18, 14);
    layout->setSpacing(6);

    m_label = new QLabel(label.toUpper(), this);
    m_label->setFont(uiFont(10, QFont::DemiBold));
    m_label->setStyleSheet(QString("color:%1;background:transparent;").arg(Style::css(KtaColors::Text4)));
    m_value = new QLabel("-", this);
    m_value->setFont(monoFont(22));
    m_value->setStyleSheet(QString("color:%1;background:transparent;font-weight:600;").arg(Style::css(valueColor)));
    m_subtext = new QLabel(QString(), this);
    m_subtext->setFont(uiFont(11));
    m_subtext->setStyleSheet(QString("color:%1;background:transparent;").arg(Style::css(KtaColors::Text3)));

    layout->addWidget(m_label);
    layout->addWidget(m_value);
    layout->addWidget(m_subtext);
}

void StatCard::setValue(const QString &value) { m_value->setText(value); }
void StatCard::setSubtext(const QString &subtext) { m_subtext->setText(subtext); }

void StatCard::paintEvent(QPaintEvent *)
{
    QPainter p(this);
    p.setRenderHint(QPainter::Antialiasing);
    QRectF r = rect().adjusted(0.5, 0.5, -0.5, -0.5);
    p.setBrush(KtaColors::BgCard);
    p.setPen(QPen(KtaColors::Border, 1));
    p.drawRoundedRect(r, 10, 10);
}
