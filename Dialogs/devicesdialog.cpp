#include "devicesdialog.h"
#include "ui_devicesdialog.h"
#include <QPushButton>

DevicesDialog::DevicesDialog(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::DevicesDialog)
{
    ui->setupUi(this);
    ui->TableWidget->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
    refreshDevices();

    connect(ui->RefreshButton, &QPushButton::clicked, this, &DevicesDialog::refreshDevices);
}

DevicesDialog::~DevicesDialog()
{
    delete ui;
}

const int DevicesDialog::getDelayTime() const
{
    return ui->DelayTimeSpinBox->value();
}

const int DevicesDialog::getSnapLength() const
{
    return ui->SnapSpinBox->value();
}

const bool DevicesDialog::getIsPromiscuous() const
{
    return ui->PromiscuousCheckBox->isChecked();
}

const QString DevicesDialog::getDeviceName() const
{
    return ui->TableWidget->item(ui->TableWidget->currentRow(), 0)->text();
}

const QString DevicesDialog::getDeviceDescription() const
{
    return ui->TableWidget->item(ui->TableWidget->currentRow(), 1)->text();
}

void DevicesDialog::refreshDevices()
{
    QStringList devicesNameList;
    QStringList devicesDescriptionList;
    char *errbuf = (char *) malloc(sizeof(char) * 100);
    pcap_if_t *devices;
    if (pcap_findalldevs(&devices, errbuf) != -1) {
        while (devices) {
            devicesNameList.append(devices->name);
            devicesDescriptionList.append(devices->description);
            devices = devices->next;
        }
    }
    free(errbuf);

    const int preCount = ui->TableWidget->rowCount();
    for (int i = 0; i < preCount; ++i)
        ui->TableWidget->removeRow(0);

    for (int i = 0; i < devicesNameList.count(); ++i) {
        ui->TableWidget->insertRow(i);
        ui->TableWidget->setItem(i, 0, new QTableWidgetItem(devicesNameList.at(i)));
        ui->TableWidget->setItem(i, 1, new QTableWidgetItem(devicesDescriptionList.at(i)));
    }

    if (ui->TableWidget->rowCount())
        ui->TableWidget->selectRow(0);
    ui->TableWidget->setFocus();
}
