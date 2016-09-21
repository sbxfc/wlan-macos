//
//  ANClient.h
//  WIFISniffer-Mac
//
//  Created by sbxfc on 16/9/12.
//  Copyright © 2016年 me.rungame.sbxfc. All rights reserved.
//

#import <Foundation/Foundation.h>


@interface ANClient : NSObject {

}

@property (readwrite) int packetCount;
@property (readwrite) int deauthsSent;
@property (readonly) unsigned char * macAddress;
@property (readonly) unsigned char * bssid;
@property (readwrite) float rssi;
@property (readwrite) BOOL enabled;

- (id)initWithMac:(const unsigned char *)mac bssid:(const unsigned char *)aBSSID;

@end