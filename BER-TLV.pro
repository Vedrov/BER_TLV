#-------------------------------------------------
#
# Project created by QtCreator 2016-10-22T22:34:48
#
#-------------------------------------------------

QT       += core gui

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

TARGET = BER-TLV
TEMPLATE = app


SOURCES += main.cpp\
        mainwindow.cpp \
    decoder_tlv.cpp

HEADERS  += mainwindow.h \
    decoder_tlv.h

FORMS    += mainwindow.ui
