//
//  DeviceListWindowController.h
//  WIFISniffer-Mac
//
//  Created by sbxfc on 16/9/9.
//  Copyright © 2016年 me.rungame.sbxfc. All rights reserved.
//

#import <Cocoa/Cocoa.h>
#import "WIFISniffer.h"

@interface DeviceListWindowController : NSWindowController<WIFISnifferDelegate>


/**
 *  设置选取的网卡和WIFI热点
 *
 *  @param aps       WIFI热点
 */
-(void)setAPs:(NSArray*)aps;

@end
