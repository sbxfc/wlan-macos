#include <stdio.h>
#include <pcap.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include "ieee802_11_radio.h"

int ieee80211_field_size[32] = {
  sizeof(uint64_t),   // IEEE80211_RADIOTAP_TSFT
  sizeof(uint8_t),    // IEEE80211_RADIOTAP_FLAGS
  sizeof(uint8_t),    // IEEE80211_RADIOTAP_RATE
  2*sizeof(uint16_t), // IEEE80211_RADIOTAP_CHANNEL
  sizeof(uint16_t),   // IEEE80211_RADIOTAP_FHSS
  sizeof(int8_t),    // IEEE80211_RADIOTAP_DBM_ANTSIGNAL
  sizeof(int8_t),    // IEEE80211_RADIOTAP_DBM_ANTNOISE
  sizeof(uint16_t),   // IEEE80211_RADIOTAP_LOCK_QUALITY
  sizeof(uint16_t),   // IEEE80211_RADIOTAP_TX_ATTENUATION
  sizeof(uint16_t),   // IEEE80211_RADIOTAP_DB_TX_ATTENUATION
  sizeof(int8_t),     // IEEE80211_RADIOTAP_DBM_TX_POWER
  sizeof(uint8_t),     // IEEE80211_RADIOTAP_ANTENNA
  sizeof(uint8_t),    // IEEE80211_RADIOTAP_DB_ANTSIGNAL
  sizeof(uint8_t),    // IEEE80211_RADIOTAP_DB_ANTNOISE
};

/**
 * 解析radiotap数据
 * @param pkt 数据帧指针
 * @param field 数据类型对应的掩码位次
*/
void *get_radiotap_field(const u_char *pkt,enum ieee80211_radiotap_type field)
{
  struct ieee80211_radiotap_header* hdr = (struct ieee80211_radiotap_header*)pkt;
  int offs = sizeof(struct ieee80211_radiotap_header);/*获取radiotap里的Data的首位置*/
  char *pc = (char *)hdr;
  int i;
  for(i = 0; i < field; i++) {
    /**
     * 要获取掩码对应的Data数据,
     * 首先要加上前面数据的size来获取当前掩码对应数据的首地址
     */
    if(hdr->it_present & (1 << i)) {
      offs += ieee80211_field_size[i];
    }
  }

  if((ieee80211_field_size[field] > 1) && (offs %2)) {
    offs++;
  }
  pc = pc + offs;
  return (void *)pc;
}

/*获取80211携带的帧数据,即MPDU部分*/
void *get_80211_frame(const u_char *pkt) {
    struct ieee80211_radiotap_header* hdr = (struct ieee80211_radiotap_header*)pkt;
    char *pc = (char *)hdr;
    return pc + hdr->it_len;
}
