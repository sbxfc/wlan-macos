//
//  WIFISniffer.h
//  WIFISniffer-Mac
//
//  Created by sbxfc on 16/9/12.
//  Copyright © 2016年 me.rungame.sbxfc. All rights reserved.
//

#import <Foundation/Foundation.h>
@class WIFISniffer;
@class IEEE_80211_Packet;
@class CWChannel;

@protocol WIFISnifferDelegate <NSObject>

- (void)wifiSniffer:(WIFISniffer *)sniffer failedWithError:(NSError *)error;
- (void)wifiSniffer:(WIFISniffer *)sniffer gotPacket:(IEEE_80211_Packet *)packet;

@end

@interface WIFISniffer : NSObject

@property (nonatomic, assign) id<WIFISnifferDelegate> delegate;

/**
 *  开始抓包
 */
-(void)start;

- (void)setChannel:(CWChannel *)channel;


@end
