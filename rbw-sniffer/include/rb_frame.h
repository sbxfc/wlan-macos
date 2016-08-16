
#include "ieee802_11_radio.h"

/**
 * 打印出RadioTap信息
 * @param data RadioTap指针
*/
void print_radiotap_header(const u_char * packet);

/**
 * 打印出控制帧信息
 * @param data 控制帧数据指针
*/
void print_frame_control_info(const int16_t * data);

/**
 * 获取是否为发送至AP的数据帧
 * @param data 控制帧数据指针
*/
int is_send_to_ap(const int16_t * data);

/**
 * 获取是否为AP发出的数据帧
 * @param data 控制帧数据指针
*/
int is_send_by_ap(const int16_t * data);

/**
 * 打印出Beacon信息
 * @param data
*/
void print_beacon (const u_char * packet);

/**
 * 输出由AP发出的数据帧
*/
void print_from_ap_frame(const u_char * packet);

/**
 * 发送至AP的数据帧
*/
void print_to_ap_frame(const u_char * packet);
