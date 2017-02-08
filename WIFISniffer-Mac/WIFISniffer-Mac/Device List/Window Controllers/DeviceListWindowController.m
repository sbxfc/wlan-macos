//
//  DeviceListWindowController.m
//  WIFISniffer-Mac
//
//  Created by sbxfc on 16/9/9.
//  Copyright © 2016年 me.rungame.sbxfc. All rights reserved.
//

#import "DeviceListWindowController.h"
#import "SysMacros.h"
#import "AppDelegate.h"
#import "DeviceListWindowController.h"
#import "WIFISniffer.h"
#import "IEEE_80211_Packet.h"
#import <CoreWLAN/CoreWLAN.h>
#import "mac.h"
#import "Device.h"



@interface DeviceListWindowController ()
{
    NSMutableArray* _deviceListData;/*设备列表*/
    NSArray* _selectedAPs; /*选择的WIFI热点*/
    NSTimer * hopTimer;
    WIFISniffer* sniffer;
    NSInteger channelIndex;
    NSArray * channels;
    Device* _selectedDecryptDevice;
}
@property (weak) IBOutlet NSTableView *tableView;
@property (weak) IBOutlet NSTextField *noteLabel;

@end

@implementation DeviceListWindowController




- (void)windowDidLoad {
    [super windowDidLoad];
    
    _deviceListData = @[].mutableCopy;
    
    //设置一下窗口
    [self.window setTitle:@"设备列表"];
    [self.window setContentSize:WINDOW_SIZE];
    // Implement this method to handle any initialization after your window controller's window has been loaded from its nib file.
    
    [self performSelector:@selector(fetchDevices) withObject:nil afterDelay:0.5];
}


-(void)setAPs:(NSArray*)aps
{
    _selectedAPs = aps;
}

/**
 *  设置界面
 */
-(void)configureUI
{
    
}

#pragma mark Scan Device List

- (void)hopChannel {
    channelIndex += 1;
    if (channelIndex >= [channels count]) {
        channelIndex = 0;
    }
    [sniffer setChannel:[channels objectAtIndex:channelIndex]];
}

/**
 *  扫描指定WIFI热点下连接的设备列表
 */
-(void)fetchDevices
{
    NSMutableArray * mChannels = [[NSMutableArray alloc] init];
    for (CWNetwork * net in _selectedAPs) {
        if (![mChannels containsObject:net.wlanChannel]) {
            [mChannels addObject:net.wlanChannel];
        }
    }
    channels = [mChannels copy];
    channelIndex = -1;
    [self hopChannel];
    hopTimer = [NSTimer scheduledTimerWithTimeInterval:0.25 target:self selector:@selector(hopChannel) userInfo:nil repeats:YES];
    
    sniffer = [[WIFISniffer alloc] init];
    [sniffer setDelegate:self];
    [sniffer start];
}

- (void)wifiSniffer:(WIFISniffer *)sniffer failedWithError:(NSError *)error {
//    NSRunAlertPanel(@"Sniff Error", @"Got a sniff error. Please try again.", @"OK", nil, nil);
}

- (BOOL)includesBSSID:(const unsigned char *)bssid {
    for (CWNetwork * network in _selectedAPs) {
        if ([MACToString(bssid) isEqualToString:network.bssid]) {
            return YES;
        }
    }
    return NO;
}

#pragma mark WIFI Sniffer Delegate

- (void)wifiSniffer:(WIFISniffer *)sniffer gotPacket:(IEEE_80211_Packet *)packet
{
    BOOL hasClient = NO;
    unsigned char client[6];
    unsigned char bssid[6];
    if ([packet dataFCS] != [packet calculateFCS]) return;
    
    
    if (packet.macHeader->frame_control.from_ds == 0 && packet.macHeader->frame_control.to_ds == 1) {
        memcpy(bssid, packet.macHeader->mac1, 6);
        if (![self includesBSSID:bssid]) return;
        memcpy(client, packet.macHeader->mac2, 6);
        hasClient = YES;
    }
    else if (packet.macHeader->frame_control.from_ds == 0 && packet.macHeader->frame_control.to_ds == 0) {
        memcpy(bssid, packet.macHeader->mac3, 6);
        if (![self includesBSSID:bssid]) return;
        if (memcmp(packet.macHeader->mac2, packet.macHeader->mac3, 6) != 0) {
            memcpy(client, packet.macHeader->mac2, 6);
            hasClient = YES;
        }
    }
    else if (packet.macHeader->frame_control.from_ds == 1 && packet.macHeader->frame_control.to_ds == 0) {
        memcpy(bssid, packet.macHeader->mac2, 6);
        if (![self includesBSSID:bssid]) return;
        memcpy(client, packet.macHeader->mac1, 6);
        hasClient = YES;
    }
    
    if (client[0] == 0x33 && client[1] == 0x33) hasClient = NO;
    if (client[0] == 0x01 && client[1] == 0x00) hasClient = NO;
    if (client[0] == 0xFF && client[1] == 0xFF) hasClient = NO;
    
    if (hasClient) {
        Device * clientObj = [[Device alloc] initWithMac:client bssid:bssid];
        if (![_deviceListData containsObject:clientObj]) {
            [_deviceListData addObject:clientObj];
        } else {
            Device * origClient = [_deviceListData objectAtIndex:[_deviceListData indexOfObject:clientObj]];
            origClient.packetCount += 1;
            origClient.rssi = (float)packet.rssi;
        }
        [self.tableView reloadData];
        
        
        [self fetchEAPDataOverWLAN:clientObj withPacket:packet];
    }
}

#pragma mark Fetch EAPOL Data


/***
 * 在无线局域网下捕获EAP协议数据
 */
-(void)fetchEAPDataOverWLAN:(Device *)client withPacket:(IEEE_80211_Packet *)packet {
    if(_selectedDecryptDevice){
        NSString* target = MACToString(client.macAddress);
        NSString* src = MACToString(_selectedDecryptDevice.macAddress);
        if([target isEqualToString:src]){
            [self.noteLabel setStringValue:[NSString stringWithFormat:@"分析数据包~%@",[NSDate date]]];
            if(packet.macHeader->frame_control.type == 0x02 && packet.macHeader->frame_control.subtype == 0x08){
                [self.noteLabel setStringValue:[NSString stringWithFormat:@"Qos Data~%@",[NSDate date]]];
            }
        }
    }
}


#pragma mark NSTableView Delegate

- (NSInteger)numberOfRowsInTableView:(NSTableView *)tableView {
    return [_deviceListData count];
}


- (void)tableViewSelectionDidChange:(NSNotification *)notification {
    
    
}

#pragma mark NSTableView DataSource

- (id)tableView:(NSTableView *)tableView objectValueForTableColumn:(NSTableColumn *)tableColumn row:(NSInteger)row {
    
    Device * client = [_deviceListData objectAtIndex:row];
    if ([[tableColumn identifier] isEqualToString:@"station"]) {
        return MACToString(client.macAddress);
    } else if ([[tableColumn identifier] isEqualToString:@"pkt"]) {
        return [NSNumber numberWithInteger:client.packetCount];
    } else if ([[tableColumn identifier] isEqualToString:@"rssi"]) {
        return [NSNumber numberWithFloat:client.rssi];
    }
    return nil;
}




#pragma mark Actions

/**
 *  显示错误信息
 *
 *  @param msg 提示信息
 */
-(void)alertError:(NSString*)msg
{
    NSAlert *alert = [[NSAlert alloc] init];
    [alert addButtonWithTitle:@"OK"];
    [alert setMessageText:@"提示"];
    [alert setInformativeText:msg];
    [alert setAlertStyle:NSWarningAlertStyle];
    [alert beginSheetModalForWindow:self.window completionHandler:nil];
}

- (IBAction)back:(NSButton *)sender {
    AppDelegate * appDelegate=(AppDelegate*)[[NSApplication sharedApplication]delegate];
    [self.window close];
    [[appDelegate.mainWindow window] makeKeyAndOrderFront:nil];
}


//开始解密
- (IBAction)startDecrypt:(id)sender {
    NSButton* button = sender;
    
    /**
     *  选择的WIFI热点
     */
    NSMutableArray * devices = [NSMutableArray array];
    [[self.tableView selectedRowIndexes] enumerateIndexesUsingBlock:^(NSUInteger idx, BOOL *stop) {
        [devices addObject:[_deviceListData objectAtIndex:idx]];
    }];
    
    if([devices count] == 0){
        [self alertError:@"请选择一个设备!"];
        return;
    }
    
    [button setTitle:@"停止解密"];
    [self.noteLabel setStringValue:@"解密中..."];
    _selectedDecryptDevice = [devices objectAtIndex:0];
}




@end
