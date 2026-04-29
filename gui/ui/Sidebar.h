#pragma once
#include <QWidget>
#include <QVector>
class QLabel;
class QPushButton;

class Sidebar : public QWidget
{
    Q_OBJECT
public:
    explicit Sidebar(QWidget *parent = nullptr);
    void setCurrentIndex(int index);
    void setAnomalyCount(int count);
signals:
    void currentChanged(int index);
private:
    QVector<QPushButton *> m_buttons;
    QLabel *m_badge = nullptr;
};
