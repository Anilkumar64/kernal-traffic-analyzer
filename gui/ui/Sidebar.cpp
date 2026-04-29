#include "Sidebar.h"
#include <QHBoxLayout>
#include <QLabel>
#include <QPushButton>
#include <QStyle>
#include <QVBoxLayout>

Sidebar::Sidebar(QWidget *parent) : QWidget(parent)
{
    setFixedWidth(180);
    setStyleSheet("Sidebar{background:#1c1c1c;} QPushButton{border:0;text-align:left;padding:11px 14px;color:#9a9a9a;background:#1c1c1c;font-size:14px;} QPushButton:hover{background:#242428;color:#cccccc;} QPushButton[active=\"true\"]{border-left:2px solid #4a9eff;background:#2a2a2e;color:#ffffff;} QLabel{background:#e05252;color:white;border-radius:7px;padding:0 5px;font-size:10px;}");
    auto *layout = new QVBoxLayout(this);
    layout->setContentsMargins(0, 10, 0, 0);
    layout->setSpacing(0);
    const QStringList names = {"Connections", "Processes", "DNS", "Anomalies", "Routes", "History", "Network Perf"};
    for (int i = 0; i < names.size(); ++i) {
        auto *row = new QWidget(this);
        auto *rowLayout = new QHBoxLayout(row);
        rowLayout->setContentsMargins(0, 0, 8, 0);
        rowLayout->setSpacing(0);
        auto *button = new QPushButton(names[i], row);
        rowLayout->addWidget(button, 1);
        if (i == 3) {
            m_badge = new QLabel(row);
            m_badge->hide();
            rowLayout->addWidget(m_badge);
        }
        layout->addWidget(row);
        m_buttons.append(button);
        connect(button, &QPushButton::clicked, this, [this, i] { emit currentChanged(i); });
    }
    layout->addStretch();
    setCurrentIndex(0);
}

void Sidebar::setCurrentIndex(int index)
{
    for (int i = 0; i < m_buttons.size(); ++i) {
        m_buttons[i]->setProperty("active", i == index);
        m_buttons[i]->style()->unpolish(m_buttons[i]);
        m_buttons[i]->style()->polish(m_buttons[i]);
    }
}

void Sidebar::setAnomalyCount(int count)
{
    if (!m_badge) return;
    m_badge->setText(QString::number(count));
    m_badge->setVisible(count > 0);
}
