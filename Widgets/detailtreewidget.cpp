#include "detailtreewidget.h"

DetailTreeWidget::DetailTreeWidget(QWidget *parent)
    : QTreeWidget(parent)
{
    setColumnWidth(0, 200);
    protocolColors["Transmission Control Protocol"] = QColor(231, 230, 255);
    protocolColors["Internet Protocol"] = QColor(250, 240, 215);
    protocolColors["Ethernet"] = QColor(245, 245, 245);
    protocolColors["User Datagram Protocol"] = QColor(252, 224, 255);
}

void DetailTreeWidget::setDisplayInfo(DisplayProtocol *protocol)
{
    clear();
    DisplayProtocol *p = protocol;
    while (p)
    {
        QTreeWidgetItem *topItem = new QTreeWidgetItem;
        topItem->setFont(0, QFont("Consolas"));
        topItem->setFont(1, QFont("Consolas"));
        topItem->setText(0, p->typeName);
        topItem->setText(1, p->dispInfo);
        topItem->setBackground(0, protocolColors[p->typeName]);
        topItem->setBackground(1, protocolColors[p->typeName]);

        for (int i = 0; i < p->propertys.count(); ++i) {
            QTreeWidgetItem *childItem = new QTreeWidgetItem;
            childItem->setFont(0, QFont("Consolas"));
            childItem->setFont(1, QFont("Consolas"));
            childItem->setText(0, p->propertys.at(i).first);
            childItem->setText(1, p->propertys.at(i).second);
            topItem->addChild(childItem);
        }

        addTopLevelItem(topItem);
        p = p->child;
    }
    expandAll();
}
