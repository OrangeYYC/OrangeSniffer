#include "mainwindow.h"

#include <QMetaType>
#include <pcap/pcap.h>
#include <QApplication>
#include <QStyleFactory>
#include <QDebug>
#include <QProxyStyle>
#include <QTabBar>

class OrangeStyle : public QProxyStyle
{
public:
    void polish(QWidget *widget) override {
        widget->setWindowFlags(widget->windowFlags() | Qt::NoDropShadowWindowHint);
        QProxyStyle::polish(widget);
    }
    void drawPrimitive(PrimitiveElement element, const QStyleOption *option, QPainter *painter, const QWidget *widget = nullptr) const override {
        if (element == QStyle::PE_FrameTabBarBase)
            return;
        return QProxyStyle::drawPrimitive(element, option, painter, widget);
    }
};

int main(int argc, char *argv[])
{
    QApplication::setAttribute(Qt::AA_EnableHighDpiScaling);
    QApplication a(argc, argv);
    a.setStyle(new OrangeStyle);
    a.setFont(QFont("Segoe UI, Microsoft YaHei UI", 9));
    MainWindow w;
    w.show();
    return a.exec();
}
