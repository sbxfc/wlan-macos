#include <stdio.h>
#include <pcap.h>
#include <time.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include "ieee802_11_radio.h"

/**
 * 根据标准时间转化为指定的时间格式
*/
void convert_format_time(time_t rawtime,char* buffer){

  struct tm * timeinfo;

  time (&rawtime);
  timeinfo = localtime (&rawtime);
  strftime (buffer,80,"%Y-%m-%d %I:%M:%S",timeinfo);
}

void hex(void *ptr, int len) {
  int i = 0;
  uint8_t *pc = ptr;
  int val = -1;
  char str[20];
  memset(str, 0, sizeof(str));
  while(len > 0) {
    do {
      if(0 == i%16) {
	printf("%04x ", i);
      }
      val = len > 0 ? *pc : -1;
      if (val >= 0) {
        printf("%02x ", val );
      } else {
        printf("   ");
      }
      str[i%16] = (val > 0x40 && val < 0x7f) ? val : '.';
      pc++;
      i++;
      len--;
      if(0 == i%16) {
	printf("  %s\n", str);
      }
    } while (i%16);
  }
}
