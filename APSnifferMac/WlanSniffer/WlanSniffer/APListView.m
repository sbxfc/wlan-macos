//
//  APListView.m
//  WlanSniffer
//
//  Created by sbxfc on 16/8/12.
//  Copyright © 2016年 me.rungame.sbxfc. All rights reserved.
//

#import "APListView.h"
#import <CoreWLAN/CoreWLAN.h>
#import <CoreWLAN/CWWiFiClient.h>

@interface APListView()<NSTableViewDelegate, NSTableViewDataSource>{
    NSScrollView* mainScrollView;
    NSTableView* apListTable;
    NSArray* apList;
    NSButton* scanButton;
}

@end

@implementation APListView

- (id)initWithFrame:(NSRect)frame {
    if ((self = [super initWithFrame:frame])) {
        
        NSInteger totalLen = 20;
        NSString* tmp =  [NSString stringWithFormat:@"%ld:",(long)totalLen];
        for (NSInteger i = 0; i < totalLen; i++) {
            tmp = [tmp stringByAppendingFormat:@"__%u",1];
        }
        NSAlert *alert=[NSAlert alertWithMessageText:tmp defaultButton:@"OK" alternateButton:@"NO" otherButton:nil informativeTextWithFormat:@"Nothing"];
        [alert runModal];
        
        mainScrollView = [[NSScrollView alloc] initWithFrame:NSMakeRect(10, 52, frame.size.width - 20, frame.size.height - 62)];
        apListTable = [[NSTableView alloc] initWithFrame:[[mainScrollView contentView] bounds]];
        [mainScrollView setDocumentView:apListTable];
        [mainScrollView setBorderType:NSBezelBorder];
        [mainScrollView setHasVerticalScroller:YES];
        [mainScrollView setHasHorizontalScroller:YES];
        [mainScrollView setAutohidesScrollers:NO];
        
        [apListTable setDataSource:self];
        [apListTable setDelegate:self];
        [apListTable setAllowsMultipleSelection:YES];
        
        NSTableColumn * channelColumn = [[NSTableColumn alloc] initWithIdentifier:@"channel"];
        [[channelColumn headerCell] setStringValue:@"CH"];
        [channelColumn setWidth:40];
        [channelColumn setEditable:YES];
        [apListTable addTableColumn:channelColumn];
        
        NSTableColumn * essidColumn = [[NSTableColumn alloc] initWithIdentifier:@"essid"];
        [[essidColumn headerCell] setStringValue:@"ESSID"];
        [essidColumn setWidth:170];
        [essidColumn setEditable:YES];
        [apListTable addTableColumn:essidColumn];
        
        NSTableColumn * bssidColumn = [[NSTableColumn alloc] initWithIdentifier:@"bssid"];
        [[bssidColumn headerCell] setStringValue:@"BSSID"];
        [bssidColumn setWidth:120];
        [bssidColumn setEditable:YES];
        [apListTable addTableColumn:bssidColumn];
        
        NSTableColumn * encColumn = [[NSTableColumn alloc] initWithIdentifier:@"enc"];
        [[encColumn headerCell] setStringValue:@"Security"];
        [encColumn setWidth:60];
        [encColumn setEditable:YES];
        [apListTable addTableColumn:encColumn];
        
        NSTableColumn * rssiColumn = [[NSTableColumn alloc] initWithIdentifier:@"rssi"];
        [[rssiColumn headerCell] setStringValue:@"RSSI"];
        [rssiColumn setWidth:60];
        [rssiColumn setEditable:YES];
        [apListTable addTableColumn:rssiColumn];
        
        [self setAutoresizesSubviews:YES];
        [self setAutoresizingMask:(NSViewWidthSizable | NSViewHeightSizable)];
        [self addSubview:mainScrollView];
        [mainScrollView setAutoresizingMask:(NSViewWidthSizable | NSViewHeightSizable)];

        //扫描按钮
        scanButton = [[NSButton alloc] initWithFrame:NSMakeRect(10, 10, 100, 24)];
        [scanButton setBezelStyle:NSRoundedBezelStyle];
        [scanButton setTitle:@"Scan"];
        [scanButton setTarget:self];
        [scanButton setAction:@selector(scanHandler:)];
        [scanButton setFont:[NSFont systemFontOfSize:13]];
        [self addSubview:scanButton];
        
    }
    return self;
}

#pragma mark NSTableView Delegate

- (NSInteger)numberOfRowsInTableView:(NSTableView *)tableView {
    return [apList count];
}

- (void)tableViewSelectionDidChange:(NSNotification *)notification {
    if ([[apListTable selectedRowIndexes] count] > 0) {
        NSLog(@"Hahahahahahahha~");
    }
}

#pragma mark NSTableView DataSource

- (id)tableView:(NSTableView *)tableView objectValueForTableColumn:(NSTableColumn *)tableColumn row:(NSInteger)row {
    CWNetwork * network = [apList objectAtIndex:row];
    
    if ([[tableColumn identifier] isEqualToString:@"channel"]) {
        return [NSNumber numberWithInt:(int)network.wlanChannel.channelNumber];
    } else if ([[tableColumn identifier] isEqualToString:@"essid"]) {
        return network.ssid;
    } else if ([[tableColumn identifier] isEqualToString:@"bssid"]) {
        return network.bssid;
    } else if ([[tableColumn identifier] isEqualToString:@"enc"]) {
        return [self securityTypeString:network];
    } else if ([[tableColumn identifier] isEqualToString:@"rssi"]) {
        return [[NSNumber numberWithInteger:network.rssiValue] description];
    }
    return nil;
}

- (NSString *)securityTypeString:(CWNetwork *)network {
    if ([network supportsSecurity:kCWSecurityDynamicWEP]) {
        return @"WEP";
    } else if ([network supportsSecurity:kCWSecurityNone]) {
        return @"Open";
    } else if ([network supportsSecurity:kCWSecurityEnterprise]) {
        return @"Enterprise";
    } else {
        return @"WPA";
    }
}

#pragma mark Scan The APs

/**
 * 扫描网络
 */
- (void)scanHandler:(id)sender {
    [self scanInBackground];
}

/**
 * 在后台扫描~~
 */
- (void)scanInBackground {
    dispatch_queue_t queue = dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0);
    __weak id weakSelf = self;
    dispatch_async(queue, ^{
        CWInterface * interface = [CWWiFiClient sharedWiFiClient].interface;
        NSError * error = nil;
        NSArray * nets = [[interface scanForNetworksWithSSID:nil error:&error] allObjects];
        if (error){
            NSLog(@"wifi scan error: %@", error);
            return;
        }
        if (nets) {
            [weakSelf performSelectorOnMainThread:@selector(scanSuccHandler:) withObject:nets waitUntilDone:NO];
        }
    });
}

-(void)scanErrorHandler{
    NSLog(@"Scan Error!");
}

- (void)scanSuccHandler:(NSArray *)theNetworks {
    
    NSMutableArray * newAps = [theNetworks mutableCopy];
    for (CWNetwork * ap in apList) {
        if (![newAps containsObject:ap]) {
            [newAps addObject:ap];
        }
    }
    
    apList = newAps;
    [apListTable reloadData];
}


@end
