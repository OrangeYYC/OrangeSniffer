#ifndef PRASER_H
#define PRASER_H

#include <pcap/pcap.h>
#include <winsock2.h>
#include <QString>
#include <QWidget>

struct ProtocolDetail {
    QString protocol;
    QString info;
    QWidget *widget;
    ProtocolDetail *child;

    ProtocolDetail(QString proto = "") {
        protocol = proto;
        widget = nullptr;
        child = nullptr;
        info = "";
    }
};

struct PackageDetail {
    QString time;
    QString source;
    QString destination;
    QString protocol;
    QString length;
    QString info;
};

class AbstractPraser
{
public:
    virtual ~AbstractPraser();
    virtual ProtocolDetail* prase(const u_char *content,
                                  int length,
                                  PackageDetail *info);
    virtual QString type();
};

#endif // PACKAGEPRASER_H
