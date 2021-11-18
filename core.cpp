#include "core.h"

SniffControler::SniffControler(QObject *parent) : QObject(parent)
{
    isWorking = false;
    worker = new SniffWorker;
    workerThread = new QThread;
    worker->moveToThread(workerThread);

    connect(this, &SniffControler::startWork, worker, &SniffWorker::sniff);
    connect(worker, &SniffWorker::packageReceive, this, &SniffControler::onPackageReceive);
}

bool SniffControler::open()
{
    char *errbuf = new char[1024];

    handler = pcap_open(currentSelectedDevices.toUtf8().data(),
                        snapLength,
                        (int)isPromiscuous,
                        delayTime,
                        NULL,
                        errbuf);
    if (!handler) {
        QMessageBox::critical(nullptr,
                              QString("Orange Sniffer"),
                              QString("Failed to open device.\n\nError%1").arg(errbuf),
                              QMessageBox::Ok);
        return false;
    }

    return true;
}

bool SniffControler::start()
{
    if (!open())
        return false;

    if (filter && pcap_setfilter(handler, filter) == -1) {
        QMessageBox::critical(nullptr,
                              QString("Orange Sniffer"),
                              QString("Failed to set filter."),
                              QMessageBox::Ok);
        return false;
    }
    qDebug() << "Fuck";

    workerThread->start();
    emit startWork((u_char *) handler);
    return true;
}

void SniffControler::pause()
{
    pcap_breakloop(handler);
    workerThread->quit();
    workerThread->wait();
}

void SniffControler::onPackageReceive(const pcap_pkthdr *pkthdr, const u_char *content)
{
    emit packageReceive(pkthdr, content);
}

void SniffControler::setDevices(QString _devices)
{
    char errbuf[1024];
    currentSelectedDevices = _devices;
    if(pcap_lookupnet(_devices.toUtf8().data(), &net, &mask, errbuf) == -1) {
        net = 0;
        mask = 0;
    }
}
