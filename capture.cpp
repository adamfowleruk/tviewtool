

#include "app_config.h"
#include "capture.h"
#include "type.h"

#include <stdlib.h>
#include "ble_sniffer_driver.h"

#include <string>
#include <sstream>
#include <ios>
#include <iostream>
#include <iomanip>

#include <chrono>

//cmd_buf cmdBuf;
//extern vtble myBLE;
extern unsigned char inq_type;
extern unsigned char inq_mode;
extern struct gap_read_ver_req_cmp_evt verInf;
extern struct gap_read_bdaddr_req_cmp_evt bdaddrInf;
extern struct gap_event_common_cmd_complete ret;
extern int com_port_open_success;

Capture::Capture() : m_running(false)
{
}

Capture::~Capture()
{
}

bool Capture::isRunning() {
    return m_running;
}


uint64_t TimeOffset = 0;
uint64_t StartTimestamp = 0;




struct ViewtoolPacket {
    uint8_t channel;
    uint8_t preamble1m;
    uint16_t preamble2m;
    uint64_t timestamp;
    uint8_t tenthByte;
    uint32_t accessAddress; // NOT a mac address - 4 bytes only
    uint16_t pduHeader; // this is technically the first two bytes of the payload packet, but we need it to perform parsing
    // START PDU header derived fields
    uint8_t pduType;
    uint8_t pduRfu;
    bool pduTxAddressRandom;
    bool pduReserved;
    uint8_t payloadLength;
    uint8_t payloadRfu;
    // END PDU header derived fields
    unsigned char *payloadData; // COPY of data
    uint32_t crc; // first three bytes only
};

void WINAPI getViewtoolPacket(int channel,unsigned char *data,int data_len,ViewtoolPacket *p) {
    // Load data in to the provided packet struct instance
    p->channel = channel;
    p->preamble1m = data[0];
    p->preamble2m = (uint8_t)data[2]|((uint8_t)data[1]<<8);
    p->timestamp = (uint64_t)data[3]|((uint64_t)data[4]<<8)|((uint64_t)data[5]<<16)|((uint64_t)data[6]<<24)|((uint64_t)data[7]<<32)|((uint64_t)data[8]<<40);
    p->timestamp >>= 5; // REQUIRED otherwise time bits jump all over the place
    p->tenthByte = data[9];
    p->accessAddress = data[10]|(data[11]<<8)|(data[12]<<16)|(data[13]<<24); // THIS IS CORRECT. This is just a number, NOT a mac address

    // See https://medium.com/rtone-iot-security/a-brief-overview-of-bluetooth-low-energy-79be06eab4df
    p->pduHeader = data[14]|(data[15]<<8); // logic here should be fine - we're not displaying it
    // header derived values below:-
    p->pduType = data[14]&0xF; // least significant 4 bits
    p->pduRfu = data[14]&0x10;
    p->pduTxAddressRandom = 0x40 == (data[14]&0x40);
    p->pduReserved = 0x80 == (data[14]&0x80);
    p->payloadLength = (data[15]&0x3F); // uses only the least significant bits // Note DOES NOT include CRC
    p->payloadRfu = data[15]&0xC0;

    p->payloadData = data + 16; // memcpy already done
    //assert(p->payloadData[0],data[16]); // confirm reference works
    p->crc = data[data_len - 3]|(data[data_len - 2]<<8)|(data[data_len - 1]<<16); // NOT SURE THIS IS TRUE - PROBABLY NOT
}

long invocationCount = 0;
long printoutCount = 0;

struct Advert {
    uint8_t gapType; // See https://www.bluetooth.com/specifications/assigned-numbers/generic-access-profile/
    uint8_t length;
    unsigned char* advertData; // TODO break this apart here if we can // 1-29 bytes
};

struct AdvertisingPacket {
    uint64_t advertiserAddress;
    uint8_t advertisementCount;
    Advert *adverts;
};

void WINAPI getAdvertisements(ViewtoolPacket* packet,AdvertisingPacket* toFill) {
    // TODO sanity check - ensure this is called on the right type of viewtool packet!
    unsigned char *data = packet->payloadData;
    toFill->advertiserAddress = (uint64_t)data[5]|      (((uint64_t)data[4])<<8)|
                              (((uint64_t)data[3])<<16)| (((uint64_t)data[2])<<24)|
                              (((uint64_t)data[1])<<32)| (((uint64_t)data[0])<<40); // It's actually 6 bytes!
    toFill->advertisementCount = 0;
    int pos = 6;
    // max 16 adverts can fit
    Advert ads[16];
    while (pos < packet->payloadLength) {
        ads[toFill->advertisementCount].length = data[pos++] - 1; // INCLUDES gap type byte, so minus 1 for actual data length
        ads[toFill->advertisementCount].gapType = data[pos++];
        // TODO add sanity check for length before calling memcpy (don't trust transmitted length)
        //memcpy(ads[toFill->advertisementCount].advertData, &data[pos], ads[toFill->advertisementCount].length);
        ads[toFill->advertisementCount].advertData = data + pos; // sets pointer position
        pos += ads[toFill->advertisementCount].length;

        toFill->advertisementCount++;
    }
    toFill->adverts = new Advert[toFill->advertisementCount];
    for (int i = 0;i < toFill->advertisementCount;i++) {
        toFill->adverts[i] = ads[i];
    }
}

struct ScanRequest {
    uint64_t scanningAddress; // 6 bytes
    uint64_t advertisingAddress; // 6 bytes
};

void WINAPI getScanRequest(ViewtoolPacket* packet,ScanRequest* toFill) {
    unsigned char *data = packet->payloadData;
    toFill->scanningAddress = (uint64_t)data[5]|      (((uint64_t)data[4])<<8)|
                              (((uint64_t)data[3])<<16)| (((uint64_t)data[2])<<24)|
                              (((uint64_t)data[1])<<32)| (((uint64_t)data[0])<<40); // It's actually 6 bytes!
    toFill->advertisingAddress = (uint64_t)data[11]|      (((uint64_t)data[10])<<8)|
                              (((uint64_t)data[9])<<16)| (((uint64_t)data[8])<<24)|
                              (((uint64_t)data[7])<<32)| (((uint64_t)data[6])<<40); // It's actually 6 bytes!
}

struct DataPacket {
    uint32_t mic;

    bool hasL2capHeader;
    uint32_t l2capHeader; // optional

    bool hasOperationCode;
    uint8_t operationCode; // optional, make l2Header required

    uint8_t payloadLength; // required, can be 0, derived from remaining length
    unsigned char *payload; // required
};

void WINAPI getData(ViewtoolPacket* p,DataPacket* d) {
    unsigned char *data = p->payloadData;
    // get mic from end first
    uint8_t pl = p->payloadLength;
    d->mic = data[pl - 4]|(data[pl - 3]<<8)|(data[pl - 2]<<16)|(data[pl - 1]<<24);
    pl -= 4; // don't treat the mac as data for the remainder of this method

    // defaults
    d->hasL2capHeader = false;
    d->hasOperationCode = false;
    d->payloadLength = 0;

    // See if big enough for L2 CAP data, end extract
    if (pl >= 4) {
        d->hasL2capHeader = true;
        d->l2capHeader = data[pl] | data[pl + 1]<<8 | data[pl + 2]<<16 | data[pl + 3]<<24;
        if (pl >= 5) {
            d->hasOperationCode = true;
            d->operationCode = data[pl + 4];
            d->payload = data + 4 + 4 + 1;
            d->payloadLength = pl - (4 + 1);
        } else {
            d->payload = data + 4 + 4;
            d->payloadLength = pl - 4;
        }
    } else {
        d->payload = data + 4;
        d->payloadLength = pl;
    }
}

template< typename T >
std::string int_to_hex( T i )
{
  std::stringstream stream;
  stream << "0x"
         << std::setfill ('0') << std::setw(sizeof(T)*2)
         << std::hex << i;
  return stream.str();
}


template< typename T >
std::string int_to_hex_address( T i )
{
  std::stringstream stream;
  stream << std::setfill ('0') << std::setw(sizeof(T)*2)
         << std::hex << i;
  return stream.str();
}

char hexDigits[] = {'0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f'};
std::string hexDigit(uint8_t numeric) {
    return std::string({hexDigits[numeric>>4],hexDigits[numeric&0xf]});
}

std::string uint8_to_hex(uint8_t theInt) {
    std::stringstream stream;
    stream << "0x" << hexDigit(theInt);
    return stream.str();
}

std::string WINAPI addressAsString(uint32_t data) {
    std::stringstream stream;
    stream << hexDigit((uint8_t)(data&0x00000FF)) << ":" << hexDigit((uint8_t)((data&0x000FF00)>>8)) << ":"
           << hexDigit((uint8_t)((data&0x00FF0000)>>16)) << ":" << hexDigit((uint8_t)((data&0xFF000000)>>24));
    return stream.str();
}

std::string WINAPI macAddressAsString(uint64_t data) {
    std::stringstream stream;
    stream << hexDigit((uint8_t)((data&0x0000000000FF))) << hexDigit((uint8_t)((data&0x00000000FF00)>>8))
           << hexDigit((uint8_t)((data&0x000000FF0000)>>16)) << hexDigit((uint8_t)((data&0x0000FF000000)>>24))
           << hexDigit((uint8_t)((data&0x00FF00000000)>>32)) << hexDigit((uint8_t)((data&0xFF0000000000)>>40));
    return stream.str();
}

std::string WINAPI crcAsString(uint32_t data) {
    std::stringstream stream;
    stream << hexDigit((uint8_t)(data&0x00000FF)) << hexDigit((uint8_t)((data&0x000FF00)>>8))
           << hexDigit((uint8_t)((data&0x00FF0000)>>16));
    return stream.str();
}

std::string WINAPI dataAsString(uint8_t length,unsigned char *data) {
    std::stringstream stream;
    for (int i = 0;i < length; i++) {
        stream << hexDigit(data[i]);
    }
    return stream.str();
}

std::string WINAPI dataAsv4UUIDString(unsigned char *data) {
    // MUST be 128 bits (16 bytes)
    std::stringstream stream;
    for (int i = 15;i >= 0;i--) {
        stream << hexDigit(data[i]);
        if (12 == i || 10 == i || 8 == i) {
            stream << "-";
        }
    }
    return stream.str();
}

std::string WINAPI advertDataAsUUIDString(Advert &ad) {
    std::stringstream stream;
    for (int i = 0;i < ad.length; i ++) {
        stream << hexDigit(ad.advertData[i]);
    }
    return stream.str();
}

void WINAPI packet_summary(ViewtoolPacket *p) {
    std::stringstream header;

    header << "Channel = " << ((uint16_t)p->channel) << ","; // upcast to prevent it being treated as a char

    if (0 == TimeOffset) {
        TimeOffset = p->timestamp;
        header << "TimeOffset = " << TimeOffset << ", ";
    }
    header << "Time = " << p->timestamp << ", ";

    // I suspect this is our device's hard coded MAC : 0x8e89bed6
    header << "AccessAddress = " << int_to_hex(p->accessAddress) << ", ";

    header << "TxAddressRandom = " << (p->pduTxAddressRandom ? "true" : "false") << ", ";

        header << "PayloadLen = " << ((uint16_t)p->payloadLength) << ", ";

        switch(p->pduType)
        {
            case 0x00://ADV_IND
            //qDebug() << headerInfo << "PDUType = ADV_IND";
            if (1) {
                AdvertisingPacket ap;
                getAdvertisements(p,&ap);
                if (ap.advertisementCount > 0) {
                    header << "CRC = " << crcAsString(p->crc) << ", PDUType = ADV_IND" << std::endl;
                    header << "  Raw data = " << dataAsString(p->payloadLength,p->payloadData) << std::endl;
                    for (int i = 0;i < ap.advertisementCount;i++) {
                        header << "  Advertiser Address: " << macAddressAsString(ap.advertiserAddress) << ", GAP Type: "
                               << uint8_to_hex(ap.adverts[i].gapType) << ", Length: " << ((uint16_t)ap.adverts[i].length)
                               << ", Data: " << advertDataAsUUIDString(ap.adverts[i]) << std::endl;
                        if (ap.adverts[i].gapType == 0x07) {
                            // service characteristic - complete list, 128 bits
                            header << "    Service v4 UUID: " << dataAsv4UUIDString(ap.adverts[i].advertData) << std::endl;
                        }
                    }
                    std::cout << header.str();
                }
                // TODO add condition here to include empty advertisers
            }

            break;
            case 0x01://ADV_DIRECT_IND
            header << "CRC = " << crcAsString(p->crc) << ", PDUType = ADV_DIRECT_IND" << std::endl;
            std::cout << header.str() << std::endl;
            break;
            case 0x02://ADV_NONCONN_IND
            header << "CRC = " << crcAsString(p->crc) << ", PDUType = ADV_NONCONN_IND" << std::endl;
            std::cout << header.str() << std::endl;
            break;
            case 0x03://SCAN_REQ
            header << "CRC = " << crcAsString(p->crc) << ", PDUType = SCAN_REQ" << std::endl;
            header << "  Raw data = " << dataAsString(p->payloadLength,p->payloadData) << std::endl;
            ScanRequest sr;
            getScanRequest(p,&sr);
            header << "  Scanning Address: " << macAddressAsString(sr.scanningAddress) << ", Advertising Address: " << macAddressAsString(sr.advertisingAddress);
            std::cout << header.str() << std::endl;
            break;
            case 0x04://SCAN_RSP
            header << "CRC = " << crcAsString(p->crc) << ", PDUType = SCAN_RSP" << std::endl;
            std::cout << header.str() << std::endl;
            break;
            case 0x05://CONNECT_REQ
            header << "CRC = " << crcAsString(p->crc) << ", PDUType = CONNECT_REQ" << std::endl;
            std::cout << header.str() << std::endl;
            break;
            case 0x06://ADV_SCAN_IND
            header << "CRC = " << crcAsString(p->crc) << ", PDUType = ADV_SCAN_IND" << std::endl;
            std::cout << header.str() << std::endl;
            break;
        default:
            std::cout << header.str() << "CRC = " << crcAsString(p->crc) << ", PDUType = UNKNOWN: " << ((uint16_t)p->pduType) << std::endl;
            break;
        }
    printoutCount++;
    if (0 == invocationCount % 100) {
        // TODO debug only
        std::cout << "Invocations: " << invocationCount << ", printouts: " << printoutCount << std::endl;
    }
}


// Adam's raw data format
void WINAPI stream_raw_data(int channel,unsigned char *data,int data_len)
{
    using namespace std::chrono;
    microseconds ms = duration_cast< microseconds >(
        system_clock::now().time_since_epoch()
    );
    ViewtoolPacket p;
    getViewtoolPacket(channel,data,data_len,&p);
    std::cout << ms.count() << ",Raw:Viewtool," << ((uint16_t)p.channel) << "," << ((uint16_t)p.preamble1m) << "," << p.preamble2m << ","
              << p.timestamp << "," << ((uint16_t)p.tenthByte) << "," << int_to_hex(p.accessAddress) << ","
              << p.pduHeader << "," << ((uint16_t)p.payloadLength) << "," << dataAsString(p.payloadLength,p.payloadData) << ","
              << crcAsString(p.crc) << std::endl;

    // For testing only:-
    //packet_summary(&p);
}

// Adam's visual debug summary format
void WINAPI stream_summary(int channel,unsigned char *data,int data_len) {
    // The below is useful for debug
    ViewtoolPacket p;
    getViewtoolPacket(channel,data,data_len,&p);

    packet_summary(&p);
}


void WINAPI get_raw_data_cb(int dev_index,int channel,unsigned char *data,int data_len)
{
    invocationCount++;
    stream_raw_data(channel,data,data_len);
}

void Capture::start(int deviceIndex)
{
    int ret = scan_dev(NULL);
        if (0 >= ret){
            std::cerr << "Error: No device connected" << std::endl;
            return;
        }
        ret = open_dev(deviceIndex);
        if (3 != ret) {
            std::cerr << "Error: Device opening failed" << std::endl;
            return;
        }
        TimeOffset = 0;
        m_running = true;
        start_get_data(deviceIndex,get_raw_data_cb);
}

