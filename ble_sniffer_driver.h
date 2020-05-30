#ifndef BLE_SNIFFER_DRIVE_H
#define BLE_SNIFFER_DRIVE_H

#ifndef WINAPI
#ifndef OS_UNIX
#define WINAPI __stdcall
#else
#define WINAPI
#endif // OS_UNIX
#endif
#include <stdint.h>


typedef void (WINAPI *bsniffer_get_raw_data_cb_fn)(int dev_index,int channel,unsigned char *data,int data_len);

#ifdef __cplusplus
extern "C"
{
#endif

int WINAPI scan_dev(uint64_t *pserial);
int WINAPI open_dev(int dev_index);
int WINAPI close_dev(int dev_index);
int WINAPI get_raw_data(int dev_index,bsniffer_get_raw_data_cb_fn get_raw_data_cb_fn,int timeout);

int WINAPI start_get_data(int dev_index,bsniffer_get_raw_data_cb_fn callback);
int WINAPI stop_get_data(int dev_index);

#ifdef __cplusplus
}
#endif


#endif // BLE_SNIFFER_DRIVE_H
