//
//  Device.m
//  WIFISniffer-Mac
//
//  Created by sbxfc on 16/9/14.
//  Copyright © 2016年 me.rungame.sbxfc. All rights reserved.
//

#import "Device.h"

@implementation Device

@synthesize packetCount;
@synthesize macAddress;
@synthesize bssid;
@synthesize rssi;
@synthesize enabled;

- (id)initWithMac:(const unsigned char *)mac bssid:(const unsigned char *)aBSSID {
    if ((self = [super init])) {
        macAddress = (unsigned char *)malloc(6);
        bssid = (unsigned char *)malloc(6);
        packetCount = 0;
        memcpy(macAddress, mac, 6);
        memcpy(bssid, aBSSID, 6);
        enabled = YES;
    }
    return self;
}

- (BOOL)isEqual:(id)object {
    if (![object isKindOfClass:[self class]]) return NO;
    Device * client = (Device *)object;
    if (memcmp(client.bssid, bssid, 6) == 0 && memcmp(client.macAddress, macAddress, 6) == 0) {
        return YES;
    }
    return NO;
}

- (void)dealloc {
    free(macAddress);
    free(bssid);
}
@end
