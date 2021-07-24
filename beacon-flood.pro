TEMPLATE = app
CONFIG += console c++11
CONFIG -= app_bundle
CONFIG -= qt
LIBS += -ltins
LIBS += -lpcap

SOURCES += \
        mac.cpp \
        main.cpp

HEADERS += \
    beacon-flood.h \
    mac.h
