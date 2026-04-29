#include "TitleBar.h"
#include "Style.h"

#include <QHBoxLayout>
#include <QLabel>
#include <QPainter>
#include <QPushButton>
#include <QWindow>

static QPushButton *makeDot(const QColor &color, QWidget *parent)
{
    auto *button = new QPushButton(parent);
    button->setFixedSize(12, 12);
    button->setCursor(Qt::PointingHandCursor);
    button->setFocusPolicy(Qt::NoFocus);
    button->setStyleSheet(QString("QPushButton{background:%1;border:none;border-radius:6px;padding:0;}").arg(Style::css(color)));
    return button;
}

TitleBar::TitleBar(QWidget *parent) : QWidget(parent)
{
    setFixedHeight(36);
    auto *layout = new QHBoxLayout(this);
    layout->setContentsMargins(12, 0, 12, 0);
    layout->setSpacing(8);

    auto *spacerLeft = new QWidget(this);
    spacerLeft->setFixedWidth(72);
    auto *title = new QLabel("Kernel Traffic Analyzer", this);
    title->setAlignment(Qt::AlignCenter);
    title->setFont(uiFont(12, QFont::Medium));
    title->setStyleSheet(QString("color:%1;background:transparent;").arg(Style::css(KtaColors::Text3)));

    auto *minimize = makeDot(KtaColors::Amber, this);
    auto *maximize = makeDot(KtaColors::Green, this);
    auto *close = makeDot(KtaColors::Red, this);
    connect(minimize, &QPushButton::clicked, this, [this] { if (window()) window()->showMinimized(); });
    connect(maximize, &QPushButton::clicked, this, [this] {
        if (!window()) return;
        window()->isMaximized() ? window()->showNormal() : window()->showMaximized();
    });
    connect(close, &QPushButton::clicked, this, [this] { if (window()) window()->close(); });

    layout->addWidget(spacerLeft);
    layout->addWidget(title, 1);
    layout->addWidget(minimize);
    layout->addWidget(maximize);
    layout->addWidget(close);
}

void TitleBar::paintEvent(QPaintEvent *)
{
    QPainter p(this);
    p.fillRect(rect(), KtaColors::BgVoid);
    p.setPen(KtaColors::Border);
    p.drawLine(rect().bottomLeft(), rect().bottomRight());
}
