#ifndef DECODER_TLV_H
#define DECODER_TLV_H

#include <QObject>
#include <QMap>

class decoder_TLV : public QObject
{
    Q_OBJECT
public:
    explicit decoder_TLV(QObject *parent = 0);
    void initMap();
    void processingTag(QByteArray *data);
    int processingLength(QByteArray *data);
    void processingData(QByteArray *data, unsigned int amountByteTag);

signals:
    void sendDataDecoding (QString dataDecoding);
    
public slots:

private:
    QMap<int, QString> TagsEMV;
    void sendShowData (QString dataDecoding);
    
};

#endif // DECODER_TLV_H
