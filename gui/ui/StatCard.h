#pragma once

#include <QWidget>

class QLabel;

class StatCard : public QWidget
{
    Q_OBJECT
public:
    explicit StatCard(const QString &label, const QColor &valueColor, QWidget *parent = nullptr);
    void setValue(const QString &value);
    void setSubtext(const QString &subtext);

protected:
    void paintEvent(QPaintEvent *event) override;

private:
    QLabel *m_label = nullptr;
    QLabel *m_value = nullptr;
    QLabel *m_subtext = nullptr;
};
