#ifndef DEVICESDIALOG_H
#define DEVICESDIALOG_H

#include <pcap/pcap.h>
#include <QDialog>

QT_BEGIN_NAMESPACE
namespace Ui { class DevicesDialog; }
QT_END_NAMESPACE

class DevicesDialog : public QDialog
{
    Q_OBJECT

public:
    explicit DevicesDialog(QWidget *parent = nullptr);
    ~DevicesDialog();

    const int getDelayTime() const;
    const int getSnapLength() const;
    const bool getIsPromiscuous() const;
    const QString getDeviceName() const;
    const QString getDeviceDescription() const;

private:
    Ui::DevicesDialog *ui;
    void refreshDevices();
};

#endif // DEVICESDIALOG_H
