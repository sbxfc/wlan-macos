//
//  IEEE_80211_Packet.h
//  WIFISniffer-Mac
//
//  Created by sbxfc on 16/9/12.
//  Copyright © 2016年 me.rungame.sbxfc. All rights reserved.
//

#import <Foundation/Foundation.h>
#include "packet.h"
#include "crc.h"

@interface IEEE_80211_Packet : NSObject {
    MACHeader * macHeader;
    unsigned char * packetData;
    unsigned char * bodyData;
    int packetLength;
    int bodyLength;
}

@property (readwrite) int rssi;

- (id)initWithData:(NSData *)data;
- (const MACHeader *)macHeader;
- (const unsigned char *)packetData;
- (const unsigned char *)bodyData;
- (int)packetLength;
- (int)bodyLength;

- (uint32_t)dataFCS;
- (uint32_t)calculateFCS;


@end
