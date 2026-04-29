#pragma once
#include <QStyledItemDelegate>

class ProtoBadgeDelegate : public QStyledItemDelegate
{
    Q_OBJECT
public:
    explicit ProtoBadgeDelegate(QObject *parent = nullptr);
    void paint(QPainter *painter, const QStyleOptionViewItem &option, const QModelIndex &index) const override;
    QSize sizeHint(const QStyleOptionViewItem &option, const QModelIndex &index) const override;
protected:
    void initStyleOption(QStyleOptionViewItem *option, const QModelIndex &index) const override;
};
