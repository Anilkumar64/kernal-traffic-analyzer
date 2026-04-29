#pragma once

#include <QPushButton>
#include <QWidget>
#include <QVector>

class QLabel;
class QGraphicsOpacityEffect;

class NavButton : public QPushButton
{
    Q_OBJECT
public:
    NavButton(const QString &icon, const QString &label, QWidget *parent = nullptr);
    void setBadge(QLabel *badge);

protected:
    void paintEvent(QPaintEvent *event) override;
    void enterEvent(QEnterEvent *event) override;
    void leaveEvent(QEvent *event) override;

private:
    QString m_icon;
    QString m_label;
    QLabel *m_badge = nullptr;
    bool m_hovered = false;
};

class Sidebar : public QWidget
{
    Q_OBJECT
public:
    explicit Sidebar(QWidget *parent = nullptr);
    void setCurrentIndex(int index);
    void setAnomalyCount(int count);
    void setModuleLoaded(bool loaded);

signals:
    void currentChanged(int index);

protected:
    void paintEvent(QPaintEvent *event) override;

private:
    QVector<NavButton *> m_buttons;
    QLabel *m_badge = nullptr;
    QLabel *m_moduleLabel = nullptr;
};
