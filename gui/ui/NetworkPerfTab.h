#pragma once
#include <QWidget>
#include "../core/ProcReader.h"
class QAbstractTableModel;

class NetworkPerfTab : public QWidget
{
    Q_OBJECT
public:
    explicit NetworkPerfTab(QWidget *parent = nullptr);
    void updateData(const ProcSnapshot &snap);
private:
    QAbstractTableModel *m_model = nullptr;
};
