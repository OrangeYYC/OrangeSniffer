#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <Dialogs/devicesdialog.h>
#include <Widgets/packagetablewidget.h>
#include <packagepraser.h>
#include <core.h>
#include <QList>
#include <QPair>
#include <pcap/pcap.h>

QT_BEGIN_NAMESPACE
namespace Ui { class MainWindow; }
QT_END_NAMESPACE

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

private:
    enum LogType{Error, Warnning, Info, Succ};
    Ui::MainWindow *ui;
    SniffControler *controler;
    QList<QPair<const pcap_pkthdr *, const u_char *>> packageList;
    QList<DisplayProtocol *> displayList;
    QLabel *snifferStateLabel;
    QLabel *packageCountLabel;
    QLabel *deviceLabel;

    void printLog(LogType type, QString text, QString detail);
    void clearLog();
    void connectActions();
    void sniffTest();

    void onActionDevicesSettings();
    void onActionStart();
    void onActionPause();
    void onPackageReceive(const pcap_pkthdr *pkthdr, const u_char *content);
    void onShowPackageDetail(QTableWidgetItem *item);
    void onFilterTextChanged(const QString &text);
    void onSetFilter();
    void onClearFilter();
};
#endif // MAINWINDOW_H
