#ifndef PACKAGEPRASER_H
#define PACKAGEPRASER_H

#include <QObject>
#include <pcap/pcap.h>
#include <QDebug>
#include <winsock2.h>
#include <QPair>

namespace Protocol {

    // Ethernet
    constexpr int ethernetHead = 14;
    constexpr int ethernetAddr = 6;
    struct ethernet
    {
        u_char etherHostD[ethernetAddr];
        u_char etherHostS[ethernetAddr];
        u_short etherType;
    };

    // IP protocol
    #define ipHead(packet) ((((struct ip *)(packet + ethernetHead))->ipHV & 0x0f) * 4)
    constexpr int ipAddr = 4;
    struct ip
    {
        u_char ipHV;
        u_char ipTos;
        u_short ipLen;
        u_short ipId;
        u_short ipOffset;
        u_char ipTtl;
        u_char ipProtocol;
        u_short ipCkSum;
        u_char ipS[ipAddr];
        u_char ipD[ipAddr];
    };

    // TCP protocol
    constexpr int tcpHead = 20;
    constexpr int tcpFIN = 0x01;
    constexpr int tcpSYN = 0x02;
    constexpr int tcpRST = 0x04;
    constexpr int tcpPSH = 0x08;
    constexpr int tcpACK = 0x10;
    constexpr int tcpURG = 0x20;
    constexpr int tcpECE = 0x40;
    constexpr int tcpCWR = 0x80;
    struct tcp
    {
        u_short tcpS;
        u_short tcpD;
        u_int tcpSeq;
        u_int tcpAck;
        u_char tcpHR;
        u_char tcpFlag;
        u_short tcpWin;
        u_short tcpCkSum;
        u_short tcpUrgP;
    };

    // UDP protocol
    struct udp
    {
        u_short udpS;
        u_short udpD;
        u_short udpLen;
        u_short udpCkSum;
    };
}

struct DisplayProtocol
{
    QString typeName;
    QString dispInfo;
    QList<QPair<QString, QString>> propertys;
    DisplayProtocol *child;
};
struct TableInfo
{
    QString time;
    QString source;
    QString destination;
    QString protocol;
    QString length;
    QString info;
};

class PackagePraser
{
public:
    static DisplayProtocol* prase(const pcap_pkthdr *pkthdr, const u_char *content, TableInfo *info);

    static DisplayProtocol* praseIP(const pcap_pkthdr *pkthdr, const u_char *content, TableInfo *info);
    static DisplayProtocol* praseTCP(const pcap_pkthdr *pkthdr, const u_char *content, TableInfo *info);
    static DisplayProtocol* praseUDP(const pcap_pkthdr *pkthdr, const u_char *content, TableInfo *info);

private:
    static QPair<QString, QString> praseTCPflag(const u_char tcpFlags);
};

#endif // PACKAGEPRASER_H
