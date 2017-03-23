#include "mainwindow.h"
#include "ui_mainwindow.h"

QMap<unsigned int, QString> TagsEMV;

MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    ui->lineEditHex->setValidator(new QRegExpValidator(QRegExp("[0-9A-F]+"), this));
    decoder = new decoder_TLV();
    connect(decoder,SIGNAL(sendDataDecoding(QString)),this,SLOT(showDataDecoding(QString)));

}

MainWindow::~MainWindow()
{
    delete ui;
    delete decoder;
}

void MainWindow::on_pushButtonConvert_clicked()
{
 QByteArray *temp = new QByteArray (QByteArray::fromHex(ui->lineEditHex->text().toLocal8Bit()));
 ui->textBrowserTLV->clear();
 decoder->processingTag(temp);
 delete temp;
}

void MainWindow::showDataDecoding(QString dataDecoding)
{
    ui->textBrowserTLV->append(dataDecoding);
}
