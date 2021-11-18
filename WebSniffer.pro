QT       += core gui

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

CONFIG += c++11

SOURCES += \
    Dialogs/devicesdialog.cpp \
    Widgets/detailtreewidget.cpp \
    Widgets/packagetablewidget.cpp \
    core.cpp \
    main.cpp \
    mainwindow.cpp \
    packagepraser.cpp

HEADERS += \
    Dialogs/devicesdialog.h \
    Widgets/detailtreewidget.h \
    Widgets/packagetablewidget.h \
    core.h \
    mainwindow.h \
    packagepraser.h

FORMS += \
    Dialogs/devicesdialog.ui \
    mainwindow.ui

# Default rules for deployment.
qnx: target.path = /tmp/$${TARGET}/bin
else: unix:!android: target.path = /opt/$${TARGET}/bin
!isEmpty(target.path): INSTALLS += target

# import npcap
win32:CONFIG(release, debug|release): LIBS += -L$$PWD/3rdParty/Npcap/Lib/x64/ -lwpcap
else:win32:CONFIG(debug, debug|release): LIBS += -L$$PWD/3rdParty/Npcap/Lib/x64/ -lwpcapd
win32:CONFIG(release, debug|release): LIBS += -L$$PWD/3rdParty/Npcap/Lib/x64/ -lPacket
else:win32:CONFIG(debug, debug|release): LIBS += -L$$PWD/3rdParty/Npcap/Lib/x64/ -lPacketd

LIBS += -lws2_32

INCLUDEPATH += $$PWD/3rdParty/Npcap/Include
DEPENDPATH += $$PWD/3rdParty/Npcap/Lib/x64

RESOURCES += \
    resources.qrc
