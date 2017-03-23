#include "decoder_tlv.h"

decoder_TLV::decoder_TLV(QObject *parent) :
    QObject(parent)
{
    initMap();
}
/*
 * «аполнение карты тегов
 */
void decoder_TLV::initMap()
{
  TagsEMV.insert(0x9F01,"Acquirer Identifier");
  TagsEMV.insert(0x9F40,"Additional Terminal Capabilities");
  TagsEMV.insert(0x81,"Amount, Authorised (Binary)");
  TagsEMV.insert(0x9F02,"Amount, Authorised (Numeric)");
  TagsEMV.insert(0x9F04,"Amount, Other (Binary)");
  TagsEMV.insert(0x9F03,"Amount, Other (Numeric)");
  TagsEMV.insert(0x9F3A,"Amount, Reference Currency");
  TagsEMV.insert(0x9F26,"Application Cryptogram");
  TagsEMV.insert(0x9F42,"Application Currency Code");
  TagsEMV.insert(0x9F44,"Application Currency Exponent");
  TagsEMV.insert(0x9F05,"Application Discretionary Data");
  TagsEMV.insert(0x5F25,"Application Effective Date");
  TagsEMV.insert(0x5F24,"Application Expiration Date");
  TagsEMV.insert(0x94,"Application File Locator (AFL)");
  TagsEMV.insert(0x4F,"Application Identifier(AID) - card");
  TagsEMV.insert(0x9F06,"Application Identifier (AID) Ц terminal");
  TagsEMV.insert(0x82,"Application Interchange Profile");
  TagsEMV.insert(0x50,"Application Label");
  TagsEMV.insert(0x9F12,"Application Preferred Name");
  TagsEMV.insert(0x5A,"Application Primary Account Number (PAN)");
  TagsEMV.insert(0x5F34,"Application Primary Account Number (PAN) Sequence Number");
  TagsEMV.insert(0x87,"Application Priority Indicator");
  TagsEMV.insert(0x9F3B,"Application Reference Currency");
  TagsEMV.insert(0x9F43,"Application Reference Currency Exponent");

  TagsEMV.insert(0x61,"Application Template");
  TagsEMV.insert(0x9F36,"Application Transaction Counter (ATC)");
  TagsEMV.insert(0x9F07,"Application Usage Control");
  TagsEMV.insert(0x9F08,"Application Version Number");
  TagsEMV.insert(0x9F09,"Application Version Number");
  TagsEMV.insert(0x89,"Authorisation Code");
  TagsEMV.insert(0x8A,"Authorisation Response Code");

  TagsEMV.insert(0x5F54,"Bank Identifier Code (BIC)");
  TagsEMV.insert(0x8C,"Card Risk Management Data Object List 1 (CDOL1)");
  TagsEMV.insert(0x8D,"Card Risk Management Data Object List 2 (CDOL2)");

  TagsEMV.insert(0x5F20,"Cardholder Name");
  TagsEMV.insert(0x9F0B,"Cardholder Name Extended");
  TagsEMV.insert(0x8E,"Cardholder Verification Method (CVM) List");
  TagsEMV.insert(0x9F34,"Cardholder Verification Method (CVM) Results");

  TagsEMV.insert(0x8F,"Certification Authority Public Key Index");
  TagsEMV.insert(0x9F22,"Certification Authority Public Key Index");

  TagsEMV.insert(0x83,"Command Template");
  TagsEMV.insert(0x9F27,"Cryptogram Information Data");
  TagsEMV.insert(0x9F45,"Data Authentication Code");
  TagsEMV.insert(0x84,"Dedicated File (DF) Name");

  TagsEMV.insert(0x9D,"Directory Definition File (DDF) Name");
  TagsEMV.insert(0x73,"Directory Discretionary Template");
  TagsEMV.insert(0x9F49,"Dynamic Data Authentication Data Object List (DDOL)");
  TagsEMV.insert(0x70,"EMV Proprietary Template");

  TagsEMV.insert(0xBF0C,"File Control Information (FCI) Issuer Discretionary Data");
  TagsEMV.insert(0xA5,"File Control Information (FCI) Proprietary Template");
  TagsEMV.insert(0x6F,"File Control Information (FCI) Template");
  TagsEMV.insert(0x9F4C,"ICC Dynamic Number");
  TagsEMV.insert(0x9F2D,"Integrated Circuit Card (ICC) PIN Encipherment Public Key Certificate");
  TagsEMV.insert(0x9F2E,"Integrated Circuit Card (ICC) PIN Encipherment Public Key Exponent");
  TagsEMV.insert(0x9F2F,"Integrated Circuit Card (ICC) PIN Encipherment Public Key Remainder");
  TagsEMV.insert(0x9F46,"Integrated Circuit Card (ICC) Public Key Certificate");
  TagsEMV.insert(0x9F47,"Integrated Circuit Card (ICC) Public Key Exponent");
  TagsEMV.insert(0x9F48,"Integrated Circuit Card (ICC) Public Key Remainder");
  TagsEMV.insert(0x9F1E,"Interface Device (IFD) Serial Number");
  TagsEMV.insert(0x5F53,"International Bank Account Number (IBAN)");
  TagsEMV.insert(0x9F0D,"Issuer Action Code Ц Default");
  TagsEMV.insert(0x9F0E,"Issuer Action Code Ц Denial");
  TagsEMV.insert(0x9F0F,"Issuer Action Code Ц Online");
  TagsEMV.insert(0x9F10,"Issuer Application Data");
  TagsEMV.insert(0x91,"Issuer Authentication Data");
  TagsEMV.insert(0x9F11,"Issuer Code Table Index");
  TagsEMV.insert(0x5F28,"Issuer Country Code");
  TagsEMV.insert(0x5F55,"Issuer Country Code (alpha2 format)");
  TagsEMV.insert(0x5F56,"Issuer Country Code (alpha3 format)");
  TagsEMV.insert(0x42,"Issuer Identification Number (IIN)");
  TagsEMV.insert(0x90,"Issuer Public Key Certificate");
  TagsEMV.insert(0x9F32,"Issuer Public Key Exponent");
  TagsEMV.insert(0x92,"Issuer Public Key Remainder");
  TagsEMV.insert(0x86,"Issuer Script Command");
  TagsEMV.insert(0x9F18,"Issuer Script Identifier");

  TagsEMV.insert(0x71,"Issuer Script Template 1");
  TagsEMV.insert(0x72,"Issuer Script Template 2");
  TagsEMV.insert(0x5F50,"Issuer URL");
  TagsEMV.insert(0x5F2D,"Language Preference");
  TagsEMV.insert(0x9F13,"Last Online Application Transaction Counter (ATC) Register");
  TagsEMV.insert(0x9F4D,"Log Entry");
  TagsEMV.insert(0x9F4F,"Log Format");
  TagsEMV.insert(0x9F14,"Lower Consecutive Offline Limit");

  TagsEMV.insert(0x9F15,"Merchant Category Code");
  TagsEMV.insert(0x9F16,"Merchant Identifier");
  TagsEMV.insert(0x9F4E,"Merchant Name and Location");

  TagsEMV.insert(0x9F17,"Personal Identification Number (PIN) Try Counter");
  TagsEMV.insert(0x9F39,"Point-of-Service (POS) Entry Mode");
  TagsEMV.insert(0x9F38,"Processing Options Data Object List (PDOL)");

  TagsEMV.insert(0x80,"Response Message Template Format 1");
  TagsEMV.insert(0x77,"Response Message Template Format 2");
  TagsEMV.insert(0x5F30,"Service Code");
  TagsEMV.insert(0x88,"Short File Identifier (SFI)");
  TagsEMV.insert(0x9F4B,"Signed Dynamic Application Data");
  TagsEMV.insert(0x93,"Signed Static Application Data");
  TagsEMV.insert(0x9F4A,"Static Data Authentication Tag List");

  TagsEMV.insert(0x9F33,"Terminal Capabilities");
  TagsEMV.insert(0x9F1A,"Terminal Country Code");
  TagsEMV.insert(0x9F1B,"Terminal Floor Limit");
  TagsEMV.insert(0x9F1C,"Terminal Identification");
  TagsEMV.insert(0x9F1D,"Terminal Risk Management Data");
  TagsEMV.insert(0x9F35,"Terminal Type");
  TagsEMV.insert(0x95,"Terminal Verification Results");

  TagsEMV.insert(0x9F1F,"Track 1 Discretionary Data");
  TagsEMV.insert(0x9F20,"Track 2 Discretionary Data");
  TagsEMV.insert(0x57,"Track 2 Equivalent Data");

  TagsEMV.insert(0x98,"Transaction Certificate (TC) Hash Value");
  TagsEMV.insert(0x97,"Transaction Certificate Data Object List (TDOL)");
  TagsEMV.insert(0x5F2A,"Transaction Currency Code");
  TagsEMV.insert(0x5F36,"Transaction Currency Exponent");
  TagsEMV.insert(0x9A,"Transaction Date");
  TagsEMV.insert(0x99,"Transaction Personal Identification Number (PIN) Data");
  TagsEMV.insert(0x9F3C,"Transaction Reference Currency Code");

  TagsEMV.insert(0x9F3D,"Transaction Reference Currency Exponent");
  TagsEMV.insert(0x9F41,"Transaction Sequence Counter");
  TagsEMV.insert(0x9B,"Transaction Status Information");
  TagsEMV.insert(0x9F21,"Transaction Time");
  TagsEMV.insert(0x9C,"Transaction Type");
  TagsEMV.insert(0x9F37,"Unpredictable Number");
  TagsEMV.insert(0x9F23,"Upper Consecutive Offline Limit");
}


/*
 * ќпределение длины данных
 * ¬озвращаемое значение - длина данных
 * Ѕайт(-ы) длины данных после определени€, удал€ютс€ из массива TLV
 * (не реализована неопределенна€ длина)
*/
int decoder_TLV::processingLength(QByteArray *data)
{
  QByteArray length;
  unsigned int byteLength = (unsigned int)data->operator [](0);

  if(byteLength <= 0x7F)
    {
     length.append(data->operator [](0));
     data->remove(0,1);
     return length.toHex().toInt(0,16);
    }
  else if(byteLength > 0x80)            //определение длины, размером - более одного байта
         {
          unsigned int i;
          for (i = 0; i <= byteLength - 0x80; i++)
              {
               length.append(data->operator [](i));
              }
          data->remove(0,i);
          return length.toHex().toInt(0,16);
         }
  return 0;
}


/*
 *ќпределение формата даных, вывод данных.
 *Ѕайт(-ы) данных после определени€, удал€ютс€ из массива TLV
*/
void decoder_TLV::processingData(QByteArray *data, unsigned int amountByteTag)
{
 if (!(data->operator [](0) & 0x20))                //TLV содержит простые данные
    {
     data->remove(0,amountByteTag);
     int length = processingLength(data);
     sendShowData(' ' + QString::fromAscii(data->left(length),length).toLocal8Bit().toHex());
     data->remove(0,length);
    }
   else
      {
       data->remove(0,amountByteTag);
       processingLength(data);
      }
}

/*
 *ќпределение тега, поиск в карте тегов.
 *ѕри отсутвии в карте тегов - отбражаетс€ как "Unknown tag"
 *Ѕайт(-ы) тега после определени€, удал€ютс€ из массива TLV
*/
void decoder_TLV::processingTag(QByteArray *data)
{
 while(!(data->isEmpty()))
      {
       QByteArray tags;
       if ((data->operator [](0) & 0x1F) == 0x1F)          //двухбайтный тег
          {
           tags.append(data->operator [](0));
           tags.append(data->operator [](1));
           if(TagsEMV.contains(tags.toHex().toInt(0,16)))
             {
              sendShowData(TagsEMV.value(tags.toHex().toInt(0,16)));
              processingData(data,2);
             }
            else
               {
                sendShowData("Unknown tag");
                processingData(data,2);
               }
          }
         else                                 //однобайтный тег
            {
             tags.append(data->operator [](0));
             if(TagsEMV.contains(tags.toHex().toInt(0,16)))
               {
                sendShowData(TagsEMV.value(tags.toHex().toInt(0,16)));
                processingData(data,1);
               }
              else
                 {
                  sendShowData("Unknown tag");
                  processingData(data,1);
                 }
            }
       }
}


void decoder_TLV::sendShowData(QString dataDecoding)
{
    emit sendDataDecoding(dataDecoding);
}
