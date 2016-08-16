
#include <stdio.h>
#include <pcap.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include "ieee802_11_radio.h"
#include "rb_radiotap_mgt.h"
#include "rb_utils.h"

/*打印出 Radiotap 控制帧信息*/
void print_radiotap_header(const u_char * packet){
    struct ieee80211_radiotap_header* hdr = (struct ieee80211_radiotap_header*)packet;

    long* rf_tsft = get_radiotap_field(packet, IEEE80211_RADIOTAP_TSFT);
    int8_t* rf_flags = get_radiotap_field(packet, IEEE80211_RADIOTAP_FLAGS);
    int8_t* rf_rate = get_radiotap_field(packet, IEEE80211_RADIOTAP_RATE);
    int16_t* rf_channel = get_radiotap_field(packet, IEEE80211_RADIOTAP_CHANNEL);
    int8_t* rf_fhss = get_radiotap_field(packet, IEEE80211_RADIOTAP_FHSS);
    int8_t* rf_antenna_signal = get_radiotap_field(packet, IEEE80211_RADIOTAP_DBM_ANTSIGNAL);
    int8_t* rf_antenna_noise = get_radiotap_field(packet, IEEE80211_RADIOTAP_DBM_ANTNOISE);
    int16_t* rf_lock_quality = get_radiotap_field(packet, IEEE80211_RADIOTAP_LOCK_QUALITY);
    int16_t* rf_tx_attenuation = get_radiotap_field(packet, IEEE80211_RADIOTAP_TX_ATTENUATION);
    int16_t* rf_db_tx_attenuation = get_radiotap_field(packet, IEEE80211_RADIOTAP_DB_TX_ATTENUATION);
    int8_t* rf_dbm_tx_power = get_radiotap_field(packet, IEEE80211_RADIOTAP_DBM_TX_POWER);
    int8_t* rf_antenna = get_radiotap_field(packet, IEEE80211_RADIOTAP_ANTENNA);
    int8_t* rf_db_antsignal = get_radiotap_field(packet, IEEE80211_RADIOTAP_DB_ANTSIGNAL);
    int8_t* rf_db_antnoise = get_radiotap_field(packet, IEEE80211_RADIOTAP_DB_ANTNOISE);

    char* time_str = malloc(80*sizeof(char));
    convert_format_time((time_t)*rf_tsft,time_str);
    printf("Radiotap Header:\n");
    printf("Version = %d,Length = %d,",hdr->it_version,hdr->it_len);
    printf("TSFT = %s ,",time_str);
    printf("Rate = 500*%d Kbs,",*rf_rate);
    printf("Antenna signal = %d dBm,",*rf_antenna_signal);
    printf("Antenna noise = %d dBm,",*rf_antenna_noise);
    printf("dBm TX power = %d dB,", *rf_dbm_tx_power);
    printf("Antenna = %d,", *rf_antenna);
    printf("dB antenna signal = %d,", *rf_db_antsignal);
    printf("dB antenna noise = %d,", *rf_db_antnoise);
    printf("\n");
    printf("\n");
    free(time_str);
}

/**
 * 打印出控制帧信息
 * @param data 控制帧数据指针
*/
void print_frame_control_info(const int16_t * data)
{
    printf("Frame Control:\n");
    printf("Protocal version 0x%02x,Type = 0x%02x,Subtype = 0x%02x,",*data & 0x03,*data >> 2 & 0x03,*data >> 4 & 0x0f);
    printf("To DS = 0x%02x,",*data >> 8 & 0x01);
    printf("From DS = 0x%02x,",*data >> 9 & 0x01);
    printf("More Flag = 0x%02x,",*data >> 10 & 0x01);
    printf("Retry = 0x%02x,",*data >> 11 & 0x01);
    printf("Pwr Mgt = 0x%02x,",*data >> 12 & 0x01);
    printf("More Data = 0x%02x,",*data >> 13 & 0x01);
    printf("WEP = 0x%02x,",*data >> 14 & 0x01);
    printf("Order = 0x%02x,",*data & 0x01);
    printf("\n");
    printf("\n");
}

/**
 * 获取是否为发送至AP的数据帧
 * @param data 控制帧数据指针
*/
int is_send_to_ap(const int16_t * data) {
  return *data >> 8 & 0x01;
}

/**
 * 获取是否为AP发出的数据帧
 * @param data 控制帧数据指针
*/
int is_send_by_ap(const int16_t * data) {
  return *data >> 9 & 0x01;
}

/**
 * 输出beacon信息
*/
void print_beacon (const u_char * packet){

    char bssid[256];
    uint8_t *mpdu = get_80211_frame(packet);

    uint8_t* ssid_flag = (uint8_t*)(mpdu + 36);
    if(*ssid_flag != 0){
      return;
    }

    uint8_t* ssid_length = (uint8_t*)(mpdu + 37);
    memset(bssid, 0, sizeof(bssid));
    memcpy(bssid, mpdu+38, *ssid_length);
    bssid[64] = 0;

    printf("AP:%s(Beacon)\n",bssid);
    //Beacon为广播包因此地址为ff:ff:ff:ff:ff:ff
	  printf("Destination Address: %02x:%02x:%02x:%02x:%02x:%02x \n",mpdu[4],mpdu[5],mpdu[6],mpdu[7],mpdu[8],mpdu[9]);
	  printf("Source Address: %02x:%02x:%02x:%02x:%02x:%02x \n",mpdu[10],mpdu[11],mpdu[12],mpdu[13],mpdu[14],mpdu[15]);
	  printf("BSS Address: %02x:%02x:%02x:%02x:%02x:%02x \n",mpdu[16],mpdu[17],mpdu[18],mpdu[19],mpdu[20],mpdu[21]);
}


/**
 * 输出由AP发出的数据帧
*/
void print_from_ap_frame(const u_char * packet){
    printf("Send from AP!!\n");

    uint8_t *mpdu = get_80211_frame(packet);
    // char bssid[256];
    //
    // uint8_t* ssid_flag = (uint8_t*)(mpdu + 36);
    // if(*ssid_flag != 0){
    //   return;
    // }
    //
    // uint8_t* ssid_length = (uint8_t*)(mpdu + 37);
    // memset(bssid, 0, sizeof(bssid));
    // memcpy(bssid, mpdu+38, *ssid_length);
    // bssid[64] = 0;

    // printf("AP:%s(Beacon)\n",bssid);
    //Beacon为广播包因此地址为ff:ff:ff:ff:ff:ff
	  printf("Destination Address: %02x:%02x:%02x:%02x:%02x:%02x \n",mpdu[10],mpdu[11],mpdu[12],mpdu[13],mpdu[14],mpdu[15]);
    printf("Source Address: %02x:%02x:%02x:%02x:%02x:%02x \n",mpdu[16],mpdu[17],mpdu[18],mpdu[19],mpdu[20],mpdu[21]);
    // printf("Destination Address: %02x:%02x:%02x:%02x:%02x:%02x \n",mpdu[4],mpdu[5],mpdu[6],mpdu[7],mpdu[8],mpdu[9]);

}

/**
 * 发送至AP的数据帧
*/
void print_to_ap_frame(const u_char * packet){
    printf("send to AP!!\n");

    uint8_t *mpdu = get_80211_frame(packet);

	  printf("Destination Address: %02x:%02x:%02x:%02x:%02x:%02x \n",mpdu[10],mpdu[11],mpdu[12],mpdu[13],mpdu[14],mpdu[15]);
    printf("Source Address: %02x:%02x:%02x:%02x:%02x:%02x \n",mpdu[16],mpdu[17],mpdu[18],mpdu[19],mpdu[20],mpdu[21]);
}
