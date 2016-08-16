#include "ieee802_11_radio.h"

/**
 * 根据掩码位来获取Data里的数据
 * @param pkt Data指针
 * @param field 数据类型对应的掩码位次
*/
void *get_radiotap_field(const u_char *pkt,enum ieee80211_radiotap_type field);

void *get_80211_frame(const u_char *pkt);
