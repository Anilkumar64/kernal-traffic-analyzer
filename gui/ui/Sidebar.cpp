#include "Sidebar.h"
#include "Style.h"

#include <QGraphicsOpacityEffect>
#include <QHBoxLayout>
#include <QLabel>
#include <QPainter>
#include <QPropertyAnimation>
#include <QVBoxLayout>

class GradientIcon : public QWidget
{
public:
    explicit GradientIcon(QWidget *parent = nullptr) : QWidget(parent) { setFixedSize(28, 28); }
protected:
    void paintEvent(QPaintEvent *) override
    {
        QPainter p(this);
        p.setRenderHint(QPainter::Antialiasing);
        QLinearGradient g(rect().bottomLeft(), rect().topRight());
        g.setColorAt(0.0, KtaColors::Accent);
        g.setColorAt(1.0, KtaColors::Purple);
        p.setPen(Qt::NoPen);
        p.setBrush(g);
        p.drawRoundedRect(rect(), 7, 7);
    }
};

class PulseDot : public QWidget
{
public:
    explicit PulseDot(QWidget *parent = nullptr) : QWidget(parent)
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
        p.setBrush(KtaColors::Green);
        p.drawEllipse(rect());
    }
};

NavButton::NavButton(const QString &icon, const QString &label, QWidget *parent)
    : QPushButton(parent), m_icon(icon), m_label(label)
{
    setCheckable(true);
    setFixedHeight(36);
    setCursor(Qt::PointingHandCursor);
    setFocusPolicy(Qt::NoFocus);
    setFont(uiFont(13));
    setStyleSheet("background:transparent;border:none;padding:0;text-align:left;");
}

void NavButton::setBadge(QLabel *badge) { m_badge = badge; }

void NavButton::enterEvent(QEnterEvent *event)
{
    m_hovered = true;
    update();
    QPushButton::enterEvent(event);
}

void NavButton::leaveEvent(QEvent *event)
{
    m_hovered = false;
    update();
    QPushButton::leaveEvent(event);
}

void NavButton::paintEvent(QPaintEvent *)
{
    QPainter p(this);
    p.setRenderHint(QPainter::Antialiasing);
    const bool active = isChecked();
    QColor text = active ? KtaColors::Text1 : (m_hovered ? KtaColors::Text2 : KtaColors::Text3);
    if (active) {
        QColor bg = KtaColors::Accent;
        bg.setAlphaF(0.08);
        p.setPen(Qt::NoPen);
        p.setBrush(bg);
        p.drawRoundedRect(rect().adjusted(0, 0, -1, -1), 6, 6);
        p.setBrush(KtaColors::Accent);
        p.drawRoundedRect(QRectF(0, 4, 2, height() - 8), 1, 1);
    } else if (m_hovered) {
        p.setPen(Qt::NoPen);
        p.setBrush(KtaColors::BgHover);
        p.drawRoundedRect(rect().adjusted(0, 0, -1, -1), 6, 6);
    }

    p.setPen(text);
    p.setFont(uiFont(14));
    p.drawText(QRect(14, 0, 20, height()), Qt::AlignVCenter | Qt::AlignLeft, m_icon);
    p.setFont(uiFont(13, active ? QFont::Medium : QFont::Normal));
    p.drawText(QRect(40, 0, width() - 70, height()), Qt::AlignVCenter | Qt::AlignLeft, m_label);
}

Sidebar::Sidebar(QWidget *parent) : QWidget(parent)
{
    setFixedWidth(192);
    auto *layout = new QVBoxLayout(this);
    layout->setContentsMargins(0, 0, 0, 0);
    layout->setSpacing(0);

    auto *header = new QWidget(this);
    header->setFixedHeight(74);
    auto *headerLayout = new QHBoxLayout(header);
    headerLayout->setContentsMargins(16, 18, 16, 14);
    headerLayout->setSpacing(10);
    headerLayout->addWidget(new GradientIcon(header));
    auto *titleBlock = new QVBoxLayout;
    titleBlock->setSpacing(1);
    auto *name = new QLabel("KTA", header);
    name->setFont(uiFont(13, QFont::DemiBold));
    name->setStyleSheet(QString("color:%1;background:transparent;").arg(Style::css(KtaColors::Text1)));
    auto *sub = new QLabel(QString::fromUtf8("v1.0 \302\267 kernel module"), header);
    sub->setFont(uiFont(10));
    sub->setStyleSheet(QString("color:%1;background:transparent;").arg(Style::css(KtaColors::Text3)));
    titleBlock->addWidget(name);
    titleBlock->addWidget(sub);
    headerLayout->addLayout(titleBlock, 1);
    layout->addWidget(header);

    auto *nav = new QWidget(this);
    auto *navLayout = new QVBoxLayout(nav);
    navLayout->setContentsMargins(8, 10, 8, 10);
    navLayout->setSpacing(1);
    const QVector<QPair<QString, QString>> items = {
        {QString::fromUtf8("\342\207\204"), "Connections"},
        {QString::fromUtf8("\342\227\210"), "Processes"},
        {QString::fromUtf8("\342\212\225"), "DNS"},
        {QString::fromUtf8("\342\232\240"), "Anomalies"},
        {QString::fromUtf8("\342\206\222"), "Routes"},
        {QString::fromUtf8("\342\227\267"), "History"},
        {QString::fromUtf8("\342\211\213"), "Network Perf"},
    };
    for (int i = 0; i < items.size(); ++i) {
        auto *row = new QWidget(nav);
        auto *rowLayout = new QHBoxLayout(row);
        rowLayout->setContentsMargins(0, 0, 0, 0);
        auto *button = new NavButton(items[i].first, items[i].second, row);
        rowLayout->addWidget(button);
        if (i == 3) {
            m_badge = new QLabel(row);
            m_badge->setFont(uiFont(10, QFont::DemiBold));
            m_badge->setAlignment(Qt::AlignCenter);
            m_badge->setStyleSheet(QString("background:%1;color:white;border-radius:10px;padding:1px 6px;").arg(Style::css(KtaColors::Red)));
            m_badge->hide();
            button->setBadge(m_badge);
            rowLayout->addWidget(m_badge);
        }
        navLayout->addWidget(row);
        m_buttons.append(button);
        connect(button, &QPushButton::clicked, this, [this, i] { emit currentChanged(i); });
    }
    layout->addWidget(nav);
    layout->addStretch();

    auto *footer = new QWidget(this);
    footer->setFixedHeight(44);
    auto *footerLayout = new QHBoxLayout(footer);
    footerLayout->setContentsMargins(16, 12, 16, 12);
    footerLayout->setSpacing(8);
    footerLayout->addWidget(new PulseDot(footer));
    m_moduleLabel = new QLabel("Waiting for module...", footer);
    m_moduleLabel->setFont(uiFont(11));
    m_moduleLabel->setStyleSheet(QString("color:%1;background:transparent;").arg(Style::css(KtaColors::Text3)));
    footerLayout->addWidget(m_moduleLabel, 1);
    layout->addWidget(footer);

    setCurrentIndex(0);
}

void Sidebar::setCurrentIndex(int index)
{
    for (int i = 0; i < m_buttons.size(); ++i) {
        m_buttons[i]->setChecked(i == index);
        m_buttons[i]->update();
    }
}

void Sidebar::setAnomalyCount(int count)
{
    if (!m_badge) return;
    m_badge->setText(QString::number(count));
    m_badge->setVisible(count > 0);
}

void Sidebar::setModuleLoaded(bool loaded)
{
    if (m_moduleLabel) m_moduleLabel->setText(loaded ? "Module loaded" : "Waiting for module...");
}

void Sidebar::paintEvent(QPaintEvent *)
{
    QPainter p(this);
    p.fillRect(rect(), KtaColors::BgSurface);
    p.setPen(KtaColors::Border);
    p.drawLine(width() - 1, 0, width() - 1, height());
    p.drawLine(0, 73, width() - 1, 73);
    p.drawLine(0, height() - 45, width() - 1, height() - 45);
}
