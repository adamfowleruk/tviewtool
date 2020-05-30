TEMPLATE = app
CONFIG += console c++11
CONFIG -= app_bundle
CONFIG -= qt

macx{
LIBS += "../libusb-1.0.0.dylib"
LIBS += "../libble_sniffer_driver.dylib"
}

SOURCES += \
        capture.cpp \
        main.cpp

HEADERS += \
    app_config.h \
    ble_sniffer_driver.h \
    capture.h \
    type.h
