#ifndef PACKAGETABLEWIDGET_H
#define PACKAGETABLEWIDGET_H

#include "../packagepraser.h"
#include <QTableWidget>
#include <QMap>

class PackageTableWidget : public QTableWidget
{
    Q_OBJECT
public:
    PackageTableWidget(QWidget *parent = nullptr);

    void append(TableInfo *protocal);
    void clear();

private:
    int packageCnt = 0;
    QMap<QString, QColor> protocolColors;
};

#endif // PACKAGETABLEWIDGET_H
