#include "mainwindow.h"
#include "ui_mainwindow.h"

#include <QStringList>
#include <QDebug>
#include <QSpacerItem>

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    ui->actionPause->setEnabled(false);
    delete takeCentralWidget();
    setDockNestingEnabled(true);
    controler = new SniffControler(this);

    deviceLabel = new QLabel("No Device Selected");
    snifferStateLabel = new QLabel("Paused");
    packageCountLabel = new QLabel("0 package sniffed");
    statusBar()->addPermanentWidget(snifferStateLabel);
    statusBar()->addPermanentWidget(packageCountLabel);
    statusBar()->addPermanentWidget(deviceLabel);

    ui->FilterLineEdit->setEnabled(false);
    ui->clearFilterButton->setEnabled(false);
    ui->setFilterButton->setEnabled(false);

    connectActions();
}

MainWindow::~MainWindow()
{
    delete ui;
}

void MainWindow::connectActions()
{
    connect(ui->actionDevice, &QAction::triggered, this, &MainWindow::onActionDevicesSettings);
    connect(ui->actionPause, &QAction::triggered, this, &MainWindow::onActionPause);
    connect(ui->actionStart, &QAction::triggered, this, &MainWindow::onActionStart);

    connect(ui->actionAboutOrangeSniffer, &QAction::triggered, [=]() {
        QMessageBox::about(this, "About Orange Sniffer", "A Package Sniffer by OrangeYYC\n\nPowered by Npcap.");
    });
    connect(ui->actionAboutQt, &QAction::triggered, [=]() {
        QMessageBox::aboutQt(this, "About Qt");
    });

    connect(controler, &SniffControler::packageReceive, this, &MainWindow::onPackageReceive);
    connect(ui->packageTableWidget, &PackageTableWidget::itemDoubleClicked, this, &MainWindow::onShowPackageDetail);

    connect(ui->clearFilterButton, &QPushButton::clicked, this, &MainWindow::onClearFilter);
    connect(ui->setFilterButton, &QPushButton::clicked, this, &MainWindow::onSetFilter);
    connect(ui->FilterLineEdit, &QLineEdit::textChanged, this, &MainWindow::onFilterTextChanged);
}

void MainWindow::printLog(LogType type, QString text, QString detail)
{
    QString colorString;
    switch (type) {
    case Error:
        colorString = QString("#AA042D");
        break;
    case Warnning:
        colorString = QString("#B78900");
        break;
    case Info:
        colorString = QString("#0000AA");
        break;
    case Succ:
        colorString = QString("#2AA198");
        break;
    }
    QString output = QString("<p><font color=%1>[%2]</font>  %3</p>").arg(colorString, text, detail);
    ui->LogTextEdit->append(output);
}

void MainWindow::clearLog()
{
    ui->LogTextEdit->clear();
}

void MainWindow::sniffTest()
{
}

void MainWindow::onActionDevicesSettings()
{
    DevicesDialog *diag = new DevicesDialog;
    if (diag->exec() == QDialog::Accepted) {
        controler->setDevices(diag->getDeviceName());
        controler->setDelayTime(diag->getDelayTime());
        controler->setSnapLength(diag->getSnapLength());
        controler->setPromiscuous(diag->getIsPromiscuous());
        setWindowTitle(QString("Orange Sniffer @ Working on %1[%2]").arg(diag->getDeviceName(), diag->getDeviceDescription()));
        deviceLabel->setText(QString("%1 [%2]").arg(diag->getDeviceName(), diag->getDeviceDescription()));
    }
    controler->open();

    if(!controler->getHandler()) {
        ui->FilterLineEdit->setEnabled(false);
        ui->clearFilterButton->setEnabled(false);
        ui->setFilterButton->setEnabled(false);
    }
    else {
        ui->FilterLineEdit->setEnabled(true);
        ui->clearFilterButton->setEnabled(true);
        ui->setFilterButton->setEnabled(true);
    }

    delete diag;
}

void MainWindow::onActionStart()
{
    if (!controler->start())
        return;
    ui->actionStart->setEnabled(false);
    ui->actionPause->setEnabled(true);
    snifferStateLabel->setText("Running");
}

void MainWindow::onActionPause()
{
    controler->pause();
    ui->actionPause->setEnabled(false);
    ui->actionStart->setEnabled(true);
    snifferStateLabel->setText("Paused");
}

void MainWindow::onPackageReceive(const pcap_pkthdr *pkthdr, const u_char *content)
{
    packageList.append(qMakePair(pkthdr, content));
    TableInfo *info = new TableInfo;
    DisplayProtocol *protocol = PackagePraser::prase(pkthdr, content, info);
    displayList.append(protocol);
    ui->packageTableWidget->append(info);
    packageCountLabel->setText(QString("%1 packages received").arg(displayList.count()));
}

void MainWindow::onShowPackageDetail(QTableWidgetItem *item)
{
    ui->PackageTreeWidget->setDisplayInfo(displayList.at(item->row()));
}

void MainWindow::onSetFilter()
{
    if (ui->FilterLineEdit->text().isEmpty()) {
        controler->clearFilter();
        return;
    }

    if (!controler->getHandler()) {
        statusBar()->showMessage("No Device Selected. Failed to set filter");
        return;
    }

    bpf_program *filter = new bpf_program;
    if (pcap_compile(controler->getHandler(),
                     filter,
                     ui->FilterLineEdit->text().toUtf8().data(),
                     0,
                     controler->getNet()) == -1) {
        statusBar()->showMessage("Failed to prase filter");
        return;
    }

    controler->setFilter(filter);
}

void MainWindow::onClearFilter()
{
    controler->clearFilter();
    statusBar()->showMessage("Filter Cleared.");
}

void MainWindow::onFilterTextChanged(const QString &text)
{
    if (text.isEmpty()) {
        ui->setFilterButton->setEnabled(false);
        ui->FilterLineEdit->setStyleSheet("background-color: rgb(255, 255, 255);");
        return;
    }

    bpf_program *filter = new bpf_program;
    if (pcap_compile(controler->getHandler(),
                     filter,
                     ui->FilterLineEdit->text().toUtf8().data(),
                     0,
                     controler->getNet()) == -1) {
        ui->FilterLineEdit->setStyleSheet("background-color: rgba(255, 0, 0, 100);");
        ui->setFilterButton->setEnabled(false);
        qDebug() << pcap_geterr(controler->getHandler());
    }
    else {
        ui->FilterLineEdit->setStyleSheet("background-color: rgba(0, 255, 0, 100);");
        ui->setFilterButton->setEnabled(true);
    }
}
