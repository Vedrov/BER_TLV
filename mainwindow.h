#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include "decoder_tlv.h"

namespace Ui {
class MainWindow;
}

class MainWindow : public QMainWindow
{
    Q_OBJECT
    
public:
    explicit MainWindow(QWidget *parent = 0);
    ~MainWindow();
    
private slots:
    void on_pushButtonConvert_clicked();
    void showDataDecoding(QString dataDecoding);

private:
    Ui::MainWindow *ui;
    decoder_TLV *decoder;
};

#endif // MAINWINDOW_H
