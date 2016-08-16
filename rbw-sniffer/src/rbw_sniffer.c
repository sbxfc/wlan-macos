
/**
 * 参见 http://rungame.me/blog/2016/06/23/wireless-lan/
*/

#include <pcap.h>
#include <time.h>
#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <pcap/pcap.h>
#include "ieee802_11_radio.h"
#include "rb_frame.h"
#include "rb_radiotap_mgt.h"
#include "rb_utils.h"

#define DEFAULT_SNAPLEN 68
#define IFNAMSIZ 16

void process_packet(u_char * args, const struct pcap_pkthdr * header, const u_char * packet);

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


void process_packet(u_char * args, const struct pcap_pkthdr * header, const u_char * packet)
{
      uint8_t *pflags;
      int8_t  *psignal;

      pflags = get_radiotap_field(packet, IEEE80211_RADIOTAP_FLAGS);
      psignal = get_radiotap_field(packet, IEEE80211_RADIOTAP_DBM_ANTSIGNAL);

      if (*pflags & 0x40) {
        // Bad FCS
        return;
      }

      //过滤掉了比较弱的信号
      //  if((*psignal) > -60){


          int16_t* frame_control = get_80211_frame(packet);
          print_radiotap_header(packet);
          print_frame_control_info(frame_control);

          switch (*frame_control >> 2 & 0x03) {
            case 0x00://管理帧
            {
              switch (*frame_control >> 4 & 0x0f) {
                case 0x00://0000
                printf("连接请求~\n");
                break;
                case 0x01://0001
                printf("连接响应~\n");
                break;
                case 0x02://0010
                printf("重连接请求~\n");
                break;
                case 0x03://0011
                printf("重连接联响应~\n");
                break;
                case 0x04://0100
                printf("探测请求~\n");
                break;
                case 0x05://0101
                printf("探测响应~\n");
                break;
                case 0x08://1000
                  print_beacon(packet);
                break;
                case 0x09://1001
                printf("通知传输指示消息~\n");
                break;
                case 0x0a://1010
                printf("解除连接~\n");
                break;
                case 0x0b://1011
                printf("身份验证~\n");
                break;
                case 0x0c://1100
                printf("解除验证~\n");
                break;
              }
            }
            break;
            case 0x01://控制帧
            {
                switch (*frame_control >> 4 & 0x0f) {
                  case 0x0a://1010
                  printf("Power Save(PS)-Poll(省电-轮询)~\n");
                  break;
                  case 0x0b://1011
                  printf("RTS~请求发送~\n");
                  break;
                  case 0x0c://1100
                  printf("CTS~清除发送~\n");
                  break;
                  case 0x0d://1101
                  printf("ACK确认~\n");
                  break;
                  case 0x0e://1110
                  printf("CF-End 无竞争周期结束~\n");
                  break;
                  case 0x0f://1111
                  printf("CF-End 无竞争周期结束~＋CF-ACK（无竞争周期确认）\n");
                  break;
                }
            }
            break;
            case 0x02://数据帧
            {
              switch (*frame_control >> 4 & 0x0f) {
                case 0x00://0000
                printf("Data~\n");
                break;
                case 0x01://0001
                printf("Data+CF-ACK~\n");
                break;
                case 0x02://0010
                printf("Data+CF-Poll~\n");
                break;
                case 0x03://0011
                printf("Data+CF-ACK+CF-Poll~\n");
                break;
                case 0x04://0100
                printf("Null data~未传送数据\n");
                break;
                case 0x05://0101
                printf("CF-ACK~\n");
                break;
                case 0x06://0110
                printf("CF-Poll~\n");
                break;
                case 0x07://0111
                printf("Data+CF-ACK+CF-Poll~\n");
                break;
                case 0x08://1000
                printf("Qos Data~\n");
                if(is_send_by_ap(frame_control)){
                    print_from_ap_frame(packet);
                }
                else if(is_send_to_ap(frame_control)){
                    print_to_ap_frame(packet);
                }
                else{
                    printf("//TODO...\n");
                }
                break;
                case 0x09://1001
                printf("Qos Data + CF-ACK~\n");
                break;
                case 0x0a://1010
                printf("Qos Data + CF-Poll~\n");
                break;
                case 0x0b://1011
                printf("Qos Data + CF-ACK+ CF-Poll~\n");
                break;
                case 0x0c://1100
                printf("QoS Null（未传送数据~\n");
                break;
                case 0x0d://1101
                printf("QoS CF-ACK（未传送数据）\n");
                break;
                case 0x0e://1110
                printf("QoS CF-Poll（未传送数据~\n");
                break;
                case 0x0f://1111
                printf("QoS CF-ACK+ CF-Poll（未传送数据\n");
                break;
              }
            }
            break;
          }

      //  }

      // hex((void *)packet, header->len);
      printf("-----------------------------------------\n");
}
