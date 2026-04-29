#pragma once

#include <QWidget>

class TitleBar : public QWidget
{
    Q_OBJECT
public:
    explicit TitleBar(QWidget *parent = nullptr);

protected:
    void paintEvent(QPaintEvent *event) override;
};
