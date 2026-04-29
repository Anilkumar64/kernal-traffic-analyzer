#pragma once
#include <QWidget>
#include "../core/AnomalyEntry.h"
class AnomalyModel;
class QLineEdit;
class QSortFilterProxyModel;
class QSystemTrayIcon;

class AnomalyTab : public QWidget
{
    Q_OBJECT
public:
    explicit AnomalyTab(QWidget *parent = nullptr);
    void updateData(const QVector<AnomalyEntry> &entries);
    int count() const;
private:
    AnomalyModel *m_model = nullptr;
    QSortFilterProxyModel *m_proxy = nullptr;
    QSystemTrayIcon *m_tray = nullptr;
    int m_lastCount = 0;
};
