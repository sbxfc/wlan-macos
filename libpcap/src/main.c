
/**
 * 参见 http://rungame.me/blog/2016/06/23/wireless-lan/
*/

#include <pcap.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <time.h>
#include <errno.h>
#include <string.h>
#include <pcap/pcap.h>
#include "ieee802_11_radio.h"

#define DEFAULT_SNAPLEN 68
#define IFNAMSIZ 16

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
void *get_radiotap_field(const u_char *pkt,
                    enum ieee80211_radiotap_type field)
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
void *get80211payload(const u_char *pkt) {
    struct ieee80211_radiotap_header* hdr = (struct ieee80211_radiotap_header*)pkt;
    char *pc = (char *)hdr;
    return pc + hdr->it_len;
}

void process_packet(u_char * args, const struct pcap_pkthdr * header, const u_char * packet)
{
      uint8_t *pc = get80211payload(packet);
      if(*pc != 0x80) {
        //过滤掉除beacon以外的帧
        return;
      }

      uint16_t *pfreq;
      uint8_t *prate;
      uint8_t *pflags;
      int64_t *pts;
      uint64_t curr_ts;
      int8_t *psignal;
      int8_t *pnoise;
      int8_t *dbm_tx_power;
      struct timeval tv;
      char bssid[256];

      gettimeofday(&tv,NULL);
      curr_ts = 1000000 * tv.tv_sec + tv.tv_usec;

      pfreq = get_radiotap_field(packet, IEEE80211_RADIOTAP_CHANNEL);
      prate = get_radiotap_field(packet, IEEE80211_RADIOTAP_RATE);
      pflags = get_radiotap_field(packet, IEEE80211_RADIOTAP_FLAGS);
      pts = get_radiotap_field(packet, IEEE80211_RADIOTAP_TSFT);
      psignal = get_radiotap_field(packet, IEEE80211_RADIOTAP_DBM_ANTSIGNAL);
      pnoise = get_radiotap_field(packet, IEEE80211_RADIOTAP_DBM_ANTNOISE);
      dbm_tx_power = get_radiotap_field(packet, IEEE80211_RADIOTAP_DBM_TX_POWER);


      if (*pflags & 0x40) {
        // Bad FCS
        return;
      }

    	uint8_t* ssid_flag = (uint8_t*)(pc + 36);
    	if(*ssid_flag != 0){
    		return;
    	}

    	uint8_t* ssid_length = (uint8_t*)(pc + 37);
      memset(bssid, 0, sizeof(bssid));
      memcpy(bssid, pc+38, *ssid_length);
      bssid[64] = 0;

      // if((*psignal) > -60){
        printf("😋 😋\n");
        printf("bssid = %s\n",bssid);
        printf("Rate = %-5d \n",500*(*prate));
        printf("Antenna signal = %d \n",*psignal);
        printf("Antenna noise = %d \n",*pnoise);
        printf("dBm TX power = %d\n", *dbm_tx_power);
        printf("\n");
      // }
}

int main(int argc, char *argv[])
{
    	pcap_t *pcap;
    	char ifname[IFNAMSIZ];/*网络接口名*/
    	char errbuf[PCAP_ERRBUF_SIZE];
    	int c;

    	ifname[0] = '\0';
    	errbuf[0] = '\0';

    	while ((c = getopt(argc, argv, ":I:c:i:r:m")) != -1)
    	{
    		switch (c) {
          case 'i':
    			case 'I':
    				if (strlen(optarg) < IFNAMSIZ) {
    					  strncpy(ifname, optarg, IFNAMSIZ);
    				}
    				else {
                printf("'%s' is not a valid interface name\n", optarg);
    				    return -1;
    				}
    				break;
    		}
    	}

    	pcap = pcap_create(ifname, errbuf);
    	pcap_set_rfmon(pcap, 1);/*设置为监视模式*/
    	pcap_set_promisc(pcap, 1);/*设置为混杂模式*/
    	pcap_set_buffer_size(pcap, 1 * 1024 * 1024);
    	pcap_set_timeout(pcap, 1);
    	pcap_set_snaplen(pcap, 16384);/*设置抓取数据包长度,DEFAULT_SNAPLEN*/
    	pcap_activate(pcap);
    	if(DLT_IEEE802_11_RADIO == pcap_datalink(pcap)) {
    		pcap_loop(pcap, -1, process_packet,NULL);
    	} else {
    		printf("Could not initialize a IEEE802_11_RADIO packet capture for interface %s\n", ifname);
    		return 1;
    	}

    	pcap_close(pcap);
    	return 0;
}
