#pragma once
#include <QWidget>
#include <QLabel>
#include <QTimer>
#include <QPropertyAnimation>
#include "../core/AnomalyEntry.h"

class AlertPopup : public QWidget
{
    Q_OBJECT
    Q_PROPERTY(qreal opacity READ windowOpacity WRITE setWindowOpacity)
public:
    explicit AlertPopup(QWidget *parent = nullptr);
    void showAlert(const AnomalyEntry &anomaly);
    void showBgpAlert(const QString &domain,
                      const QString &expected,
                      const QString &current);

protected:
    void paintEvent(QPaintEvent *e) override;
private slots:
    void dismiss();

private:
    void animateIn();
    void animateOut();
    void positionSelf();

    QLabel  *m_icon;
    QLabel  *m_title;
    QLabel  *m_body;
    QLabel  *m_sub;
    QTimer  *m_autoClose;
    bool     m_visible = false;

    static constexpr int W = 320;
    static constexpr int H = 88;
};
