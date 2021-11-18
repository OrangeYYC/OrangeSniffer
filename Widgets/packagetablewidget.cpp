#include "packagetablewidget.h"

#include <QStringList>
#include <QHeaderView>

PackageTableWidget::PackageTableWidget(QWidget *parent)
    : QTableWidget(parent)
{
    setColumnCount(7);
    QStringList headerList;
    headerList << "No." << "Time" << "Source" << "Destination" << "Protocol" << "Length" << "Info";
    setHorizontalHeaderLabels(headerList);
    horizontalHeader()->setDefaultAlignment(Qt::AlignLeft);
    horizontalHeader()->setStretchLastSection(true);
    verticalHeader()->hide();
    setSelectionBehavior(QAbstractItemView::SelectRows);
    setSelectionMode(QAbstractItemView::SingleSelection);
    setEditTriggers(QAbstractItemView::NoEditTriggers);
    setColumnWidth(0, 64);
    setColumnWidth(1, 100);
    setColumnWidth(2, 200);
    setColumnWidth(3, 200);
    setColumnWidth(4, 60);
    setColumnWidth(5, 40);

    protocolColors["TCP"] = QColor(231, 230, 255);
    protocolColors["IP"] = QColor(250, 240, 215);
    protocolColors["Eth"] = QColor(245, 245, 245);
    protocolColors["UDP"] = QColor(252, 224, 255);
}

void PackageTableWidget::append(TableInfo *protocol)
{
    packageCnt++;
    insertRow(packageCnt - 1);
    setItem(packageCnt - 1, 0, new QTableWidgetItem(QString::number(packageCnt)));
    setItem(packageCnt - 1, 1, new QTableWidgetItem(protocol->time));
    setItem(packageCnt - 1, 2, new QTableWidgetItem(protocol->source));
    setItem(packageCnt - 1, 3, new QTableWidgetItem(protocol->destination));
    setItem(packageCnt - 1, 4, new QTableWidgetItem(protocol->protocol));
    setItem(packageCnt - 1, 5, new QTableWidgetItem(protocol->length));
    setItem(packageCnt - 1, 6, new QTableWidgetItem(protocol->info));
    item(packageCnt - 1, 0)->setTextAlignment(Qt::AlignRight | Qt::AlignVCenter);
    for (int i = 0; i < 7; i++) {
        item(packageCnt - 1, i)->setBackground(protocolColors[protocol->protocol]);
        item(packageCnt - 1, i)->setFont(QFont("Consolas"));
    }
    setRowHeight(packageCnt - 1, 20);
    scrollToBottom();
}

void PackageTableWidget::clear()
{
    for (int i = 1; i <= packageCnt; ++i)
        removeRow(0);
    QTableWidget::clear();
    packageCnt = 0;
}
