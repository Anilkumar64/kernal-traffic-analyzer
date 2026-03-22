#pragma once
#include <QPushButton>
#include <QWidget>
#include <QTableWidget>
#include <QLabel>
#include "../core/DnsLeakDetector.h"

class DnsLeakTab : public QWidget
{
    Q_OBJECT
public:
    explicit DnsLeakTab(QWidget *parent = nullptr);
    void setDetector(DnsLeakDetector *detector);

public slots:
    void onEventsChanged();

private:
    void rebuild();

    DnsLeakDetector *m_detector = nullptr;
    QLabel          *m_statusBanner;
    QLabel          *m_resolverList;
    QTableWidget    *m_table;
    QPushButton     *m_clearBtn;
};
