#include "mainwindow.h"

#include <QMetaType>
#include <pcap/pcap.h>
#include <QApplication>
#include <QStyleFactory>
#include <QDebug>

int main(int argc, char *argv[])
{
    QApplication::setAttribute(Qt::AA_EnableHighDpiScaling);
    QApplication a(argc, argv);
    a.setFont(QFont("Segoe UI, Microsoft YaHei UI", 9));
    MainWindow w;
    w.show();
    return a.exec();
}
