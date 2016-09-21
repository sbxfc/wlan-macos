//
//  mac.h
//  WIFISniffer-Mac
//
//  Created by sbxfc on 16/9/14.
//  Copyright © 2016年 me.rungame.sbxfc. All rights reserved.
//

#import <Foundation/Foundation.h>

NSString * MACToString(const unsigned char * mac);
BOOL copyMAC(const char * macString, unsigned char * mac);

