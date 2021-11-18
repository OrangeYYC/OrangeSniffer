#ifndef DETAILTREEWIDGET_H
#define DETAILTREEWIDGET_H

#include <QTreeWidget>
#include <QObject>
#include "../packagepraser.h"

class DetailTreeWidget : public QTreeWidget
{
    Q_OBJECT
public:
    DetailTreeWidget(QWidget *parent = nullptr);

    void setDisplayInfo(DisplayProtocol *protocol);

private:
    QMap<QString, QColor> protocolColors;
};

#endif // DETAILTREEWIDGET_H
