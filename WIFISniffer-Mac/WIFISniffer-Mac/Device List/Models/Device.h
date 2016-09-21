//
//  Device.h
//  WIFISniffer-Mac
//
//  Created by sbxfc on 16/9/14.
//  Copyright © 2016年 me.rungame.sbxfc. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface Device : NSObject

@property NSInteger packetCount;/*数据包数量*/
@property (readonly) unsigned char * macAddress;/*mac地址*/
@property (readonly) unsigned char * bssid;
@property CGFloat rssi;
@property BOOL enabled;


- (id)initWithMac:(const unsigned char *)mac bssid:(const unsigned char *)aBSSID;

@end
