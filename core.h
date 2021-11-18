#ifndef SNIFFWORKER_H
#define SNIFFWORKER_H

#include <QDebug>
#include <QObject>
#include <QThread>
#include <QMessageBox>
#include <pcap/pcap.h>

class SniffWorker;
class SniffControler;

class SniffWorker : public QObject
{
    Q_OBJECT
public:
    explicit SniffWorker(QObject *parent = nullptr) : QObject(parent) {}
    void sniff(u_char *handler) {
        pcap_loop((pcap_t *)handler, -1, SniffWorker::callback, (u_char *)this);
    }
    static void callback(u_char *user, const pcap_pkthdr *pkthdr, const u_char *content) {
        SniffWorker *caller = (SniffWorker *) user;
        emit caller->packageReceive(pkthdr, content);
    }
signals:
    void packageReceive(const pcap_pkthdr *pkthdr, const u_char *content);
};

class SniffControler : public QObject
{
    Q_OBJECT
public:
    explicit SniffControler(QObject *parent = nullptr);

    bool open();
    bool start();
    void pause();

    pcap_t *getHandler() { return handler; }
    bpf_u_int32 getMask() { return mask; }
    bpf_u_int32 getNet() { return net; }
    void setSnapLength(int _snapLength) { snapLength = _snapLength; }
    void setDelayTime(int _delayTime) { delayTime = _delayTime; }
    void setPromiscuous(bool _promiscuous) { isPromiscuous = _promiscuous; }
    void setDevices(QString _devices);
    void setFilter(bpf_program *_filter) { filter = _filter; }
    void clearFilter() { filter = nullptr; }

signals:
    void startWork(u_char *handler);
    void packageReceive(const pcap_pkthdr *pkthdr, const u_char *content);

public slots:
    void onPackageReceive(const pcap_pkthdr *pkthdr, const u_char *content);

private:
    pcap_t *handler = nullptr;
    int snapLength = 65535;
    int delayTime = 10;
    bool isPromiscuous = true;
    bool isWorking = false;
    QString currentSelectedDevices = QString();
    bpf_program *filter = nullptr;
    bpf_u_int32 net;
    bpf_u_int32 mask;
    QThread *workerThread;
    SniffWorker *worker;
};

#endif // SNIFFWORKER_H
