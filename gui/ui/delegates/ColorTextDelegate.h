#pragma once
#include <QStyledItemDelegate>

class ColorTextDelegate : public QStyledItemDelegate
{
    Q_OBJECT
public:
    explicit ColorTextDelegate(const QColor &color, QObject *parent = nullptr);
    void paint(QPainter *painter, const QStyleOptionViewItem &option, const QModelIndex &index) const override;
    QSize sizeHint(const QStyleOptionViewItem &option, const QModelIndex &index) const override;
protected:
    void initStyleOption(QStyleOptionViewItem *option, const QModelIndex &index) const override;
private:
    QColor m_color;
};
