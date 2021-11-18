#include "packagepraser.h"
#include <QDateTime>

DisplayProtocol* PackagePraser::prase(const pcap_pkthdr *pkthdr, const u_char *content, TableInfo *info)
{
    using namespace Protocol;
    char buffer[1024];

    // Prase Header
    sprintf(buffer, "%.3f", (double)pkthdr->ts.tv_sec + pkthdr->ts.tv_usec * 0.001);;
    info->time = QDateTime::fromTime_t(pkthdr->ts.tv_sec).toString("hh:mm:ss");
    info->length = QString::number(pkthdr->len);

    // Prase Ethernet
    ethernet *ethernetHeader = (ethernet *) content;
    DisplayProtocol *ethernetNode = new DisplayProtocol;
    ethernetNode->child = nullptr;
    ethernetNode->typeName = QString("Ethernet");

    // sourceMac
    QString sourceMac;
    for (int i = 0; i < ethernetAddr; i++) {
        sprintf(buffer, "%02x:", ethernetHeader->etherHostS[i]);
        sourceMac += buffer;
    }
    sourceMac.chop(1);
    ethernetNode->propertys.append(qMakePair(QString("Source"), sourceMac));
    info->source = sourceMac;

    // destinationMac
    QString destinationMac;
    for (int i = 0; i < ethernetAddr; i++) {
        sprintf(buffer, "%02x:", ethernetHeader->etherHostD[i]);
        destinationMac += buffer;
    }
    destinationMac.chop(1);
    ethernetNode->propertys.append(qMakePair(QString("Destination"), destinationMac));
    info->destination = destinationMac;

    // DisplayInfo
    ethernetNode->dispInfo = QString("Src: %1 -> Dst: %2").arg(sourceMac, destinationMac);
    info->info = ethernetNode->dispInfo;

    // protocol
    QString type;
    u_short protocol = ntohs(ethernetHeader->etherType);
    switch (protocol) {
    case 0x0800:
        type = "IPv4";
        ethernetNode->child = praseIP(pkthdr, content, info);
        break;
    default:
        type = "UnKnown Type";
        info->protocol = "Eth";
        break;
    }
    ethernetNode->propertys.append(qMakePair(QString("Type"), type));

    return ethernetNode;
}

DisplayProtocol *PackagePraser::praseIP(const pcap_pkthdr *pkthdr, const u_char *content, TableInfo *info)
{
    using namespace Protocol;
    char buffer[1024];

    ip *ipHeader = (ip *)(content + ethernetHead);
    DisplayProtocol *ipNode = new DisplayProtocol;
    ipNode->child = nullptr;
    ipNode->typeName = QString("Internet Protocol");

    QString version = QString::number((ipHeader->ipHV & 0xF0) >> 4);
    ipNode->propertys.append(qMakePair(QString("Version"), version));

    QString headerLength = QString::number(ipHeader->ipHV & 0x0f);
    ipNode->propertys.append(qMakePair(QString("Header Length"), headerLength));

    QString typeOfService = QString::number(ipHeader->ipTos, 2);
    ipNode->propertys.append(qMakePair(QString("Type of Service"), typeOfService));

    QString totalLength = QString::number(ipHeader->ipLen);
    ipNode->propertys.append(qMakePair(QString("Total Length"), totalLength));

    QString identification = QString::number(ipHeader->ipId, 16);
    ipNode->propertys.append(qMakePair(QString("Identification"), identification));

    QString offset = QString::number(ipHeader->ipOffset);
    ipNode->propertys.append(qMakePair(QString("Offset"), offset));

    QString timeToLive = QString::number(ipHeader->ipTtl);
    ipNode->propertys.append(qMakePair(QString("Time to Live"), timeToLive));

    QString headerChecksum = QString::number(ipHeader->ipCkSum);
    ipNode->propertys.append(qMakePair(QString("Header Checksum"), headerChecksum));

    QString source;
    for (int i = 0; i < ipAddr; i++) {
        sprintf(buffer, "%d.", ipHeader->ipS[i]);
        source += buffer;
    }
    source.chop(1);
    ipNode->propertys.append(qMakePair(QString("Source IP"), source));
    info->source = source;

    QString destination;
    for (int i = 0; i < ipAddr; i++) {
        sprintf(buffer, "%d.", ipHeader->ipD[i]);
        destination += buffer;
    }
    destination.chop(1);
    ipNode->propertys.append(qMakePair(QString("Destination IP"), destination));
    info->destination = destination;

    ipNode->dispInfo = QString("Src: %1 -> Dst: %2")
            .arg(source, destination);
    info->info = ipNode->dispInfo;

    u_char protocol = ipHeader->ipProtocol;
    switch (protocol) {
    case 0x06:
        ipNode->child = PackagePraser::praseTCP(pkthdr, content, info);
        break;
    case 0x11:
        ipNode->child = PackagePraser::praseUDP(pkthdr, content, info);
        break;
    default:
        info->protocol = "IP";
        break;
    }
    return ipNode;
}

QPair<QString, QString> PackagePraser::praseTCPflag(const u_char tcpFlags)
{
    using namespace Protocol;

    QString brief, flags;

    if((tcpCWR & tcpFlags) == tcpCWR) {
        flags.append("1+++ ++++ = [CWR] Congestion Window Reduced: Set\n");
        brief.append("[CWR] ");
    } else
        flags.append("0+++ ++++ = [CWR] Congestion Window Reduced: Not Set\n");

    if((tcpECE & tcpFlags) == tcpECE) {
        flags.append("+1++ ++++ = [ECE] ECN-Echo: Set\n");
        brief.append("[ECE] ");
    } else
        flags.append("+0++ ++++ = [ECE] ECN-Echo: Not Set\n");

    if((tcpURG & tcpFlags) == tcpURG) {
        flags.append("++1+ ++++ = [UGR] Urgent: Set\n");
        brief.append("[UGR] ");
    } else
        flags.append("++0+ ++++ = [UGR] Urgent: Not Set\n");

    if((tcpACK & tcpFlags) == tcpACK) {
        flags.append("+++1 ++++ = [ACK] Acknoledgment: Set\n");
        brief.append("[ACK] ");
    } else
        flags.append("+++0 ++++ = [ACK] Acknoledgment: Not Set\n");

    if((tcpPSH & tcpFlags) == tcpPSH) {
        flags.append("++++ 1+++ = [PSH] Push: Set\n");
        brief.append("[PSH] ");
    } else
        flags.append("++++ 0+++ = [PSH] Push: Not Set\n");

    if((tcpRST & tcpFlags) == tcpRST) {
        flags.append("++++ +1++ = [RST] Reset: Set\n");
        brief.append("[RST] ");
    } else
        flags.append("++++ +0++ = [RST] Reset: Not Set\n");

    if((tcpSYN & tcpFlags) == tcpSYN) {
        flags.append("++++ ++1+ = [SYN] Syn: Set\n");
        brief.append("[SYN] ");
    } else
        flags.append("++++ ++0+ = [SYN] Syn: Not Set\n");

    if((tcpFIN & tcpFlags) == tcpFIN) {
        flags.append("++++ +++1 = [FIN] Fin: Set");
        brief.append("[FIN] ");
    } else
        flags.append("++++ +++0 = [FIN] Fin: Not Set");

    return qMakePair(brief, flags);
}

DisplayProtocol *PackagePraser::praseTCP(const pcap_pkthdr *pkthdr, const u_char *content, TableInfo *info)
{
    using namespace Protocol;

    tcp *tcpHeader = (tcp *)(content + ethernetHead + ipHead(pkthdr));
    DisplayProtocol *tcpNode = new DisplayProtocol;
    tcpNode->child = nullptr;
    tcpNode->typeName = QString("Transmission Control Protocol");
    info->protocol = QString("TCP");

    QString sourcePort = QString::number(ntohs(tcpHeader->tcpS));
    tcpNode->propertys.append(qMakePair(QString("Source Port"), sourcePort));

    QString destinationPort = QString::number(ntohs(tcpHeader->tcpD));
    tcpNode->propertys.append(qMakePair(QString("Destination Port"), destinationPort));

    QString sequenceNumber = QString::number(ntohs(tcpHeader->tcpSeq));
    tcpNode->propertys.append(qMakePair(QString("Sequence Number"), sequenceNumber));

    QString acknowledgeNumber = QString::number(ntohs(tcpHeader->tcpAck));
    tcpNode->propertys.append(qMakePair(QString("Acknowledge Number"), acknowledgeNumber));

    QString headerLength = QString::number((tcpHeader->tcpHR & 0xf0) >> 4);
    tcpNode->propertys.append(qMakePair(QString("Header Length"), headerLength));

    QPair<QString, QString> flagRes = PackagePraser::praseTCPflag(tcpHeader->tcpFlag);
    tcpNode->propertys.append(qMakePair(QString("Flags"), flagRes.second));

    QString window = QString::number(ntohs(tcpHeader->tcpWin));
    tcpNode->propertys.append(qMakePair(QString("Window"), window));

    QString checkSummary = QString::number(ntohs(tcpHeader->tcpCkSum));
    tcpNode->propertys.append(qMakePair(QString("Check Summary"), checkSummary));

    QString urgentPointer = QString::number(ntohs(tcpHeader->tcpUrgP));
    tcpNode->propertys.append(qMakePair(QString("Urgent Pointer"), urgentPointer));

    tcpNode->dispInfo = QString("%1 -> %2 %3 Seq=%4 Ack=%5 Win=%6 Len=%7")
            .arg(sourcePort, destinationPort, flagRes.first, sequenceNumber, acknowledgeNumber, window, headerLength);
    info->info = tcpNode->dispInfo;

    if (tcpHeader->tcpFlag == 0x18) {
        if (tcpHeader->tcpD == 80) {
            // HTTP
            char *http = (char*)(content + ethernetHead + ipHead(content) + tcpHead);
            qDebug() << http;
        }
    }

    return tcpNode;
}

DisplayProtocol *PackagePraser::praseUDP(const pcap_pkthdr *pkthdr, const u_char *content, TableInfo *info)
{
    using namespace Protocol;
    udp *udpHeader = (udp *)(content + ethernetAddr + ipHead(content));
    DisplayProtocol *udpNode = new DisplayProtocol;
    udpNode->child = nullptr;
    udpNode->typeName = QString("User Datagram Protocol");
    info->protocol = QString("UDP");

    QString sourcePort = QString::number(ntohs(udpHeader->udpS));
    udpNode->propertys.append(qMakePair(QString("Source Port"), sourcePort));

    QString destinationPort = QString::number(ntohs(udpHeader->udpD));
    udpNode->propertys.append(qMakePair(QString("Destination Port"), destinationPort));

    QString length = QString::number(ntohs(udpHeader->udpLen));
    udpNode->propertys.append(qMakePair(QString("Length"), length));

    QString checkSummary = QString::number(ntohs(udpHeader->udpCkSum));
    udpNode->propertys.append(qMakePair(QString("Check Summary"), checkSummary));

    udpNode->dispInfo = QString("Src Port: %1 Dst Port: %2").arg(sourcePort, destinationPort);
    info->info = udpNode->dispInfo;

    return udpNode;
}
