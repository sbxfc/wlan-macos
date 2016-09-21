//
//  WIFIListViewController.m
//  WIFISniffer-Mac
//
//  Created by sbxfc on 16/9/9.
//  Copyright © 2016年 me.rungame.sbxfc. All rights reserved.
//

#import "WIFIListViewController.h"
#import <CoreWLAN/CoreWLAN.h>
#import <CoreWLAN/CWWiFiClient.h>
#import "SysMacros.h"
#import "DeviceListWindowController.h"

@interface WIFIListViewController ()
{
    NSArray* _wListData;
}
@property (weak) IBOutlet NSView *containerView;
@property (weak) IBOutlet NSTableView *tableView;
@property (strong) DeviceListWindowController *deviceWindow;

@end

@implementation WIFIListViewController

- (void)windowDidLoad {
    [super windowDidLoad];
    
    _wListData = @[].mutableCopy;
    
    //设置一下窗口
    [self.window setTitle:@"WIFI列表"];
    [self.window setContentSize:WINDOW_SIZE];

    //开始扫描WLAN网络
    [self wlanScan:nil];
}

#pragma mark Actions
/**
 * 扫描WLAN网络
 */
- (IBAction)wlanScan:(id)sender {

    __weak id weakSelf = self;
    dispatch_queue_t queue = dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0);
    dispatch_async(queue, ^{
        CWInterface * interface = [CWWiFiClient sharedWiFiClient].interface;
        NSError * error = nil;
        NSArray * networks = [[interface scanForNetworksWithSSID:nil error:&error] allObjects];
        if (error){
            [self alertError:[NSString stringWithFormat:@"扫描失败,请检查WIFI是否已开启 [%@]",error]];
            return;
        }
        if (networks) {
            [weakSelf performSelectorOnMainThread:@selector(updateUI:) withObject:networks waitUntilDone:NO];
        }
    });
}

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

/**
 *  刷新WIFI列表
 *
 *  @param listData 扫描到的wifi热点集合
 */
- (void)updateUI:(NSArray *)wifiList {
    _wListData = [wifiList mutableCopy];
    [_tableView reloadData];
}

#pragma mark NSTableView Delegate

- (NSInteger)numberOfRowsInTableView:(NSTableView *)tableView {
    return [_wListData count];
}

- (void)tableViewSelectionDidChange:(NSNotification *)notification {
    
    /**
     *  选择的WIFI热点
     */
    NSMutableArray * aps = [NSMutableArray array];
    [[self.tableView selectedRowIndexes] enumerateIndexesUsingBlock:^(NSUInteger idx, BOOL *stop) {
        [aps addObject:[_wListData objectAtIndex:idx]];
    }];
    
    _deviceWindow = [[DeviceListWindowController alloc] initWithWindowNibName:@"DeviceListWindowController"];
    [[_deviceWindow window] center];
    [_deviceWindow setAPs:aps];
    [[_deviceWindow window] orderFront:nil];
    
    //关闭当前窗口
    [self.window orderOut:nil];
}

#pragma mark NSTableView DataSource

- (id)tableView:(NSTableView *)tableView objectValueForTableColumn:(NSTableColumn *)tableColumn row:(NSInteger)row {
    
    CWNetwork * network = [_wListData objectAtIndex:row];
    NSString* identifier = [tableColumn identifier];
    if ([identifier isEqualToString:@"channel"]){
        return [NSNumber numberWithInteger:network.wlanChannel.channelNumber];
    }else if ([identifier isEqualToString:@"essid"]) {
        return network.ssid;
    }else if ([identifier isEqualToString:@"bssid"]) {
        return network.bssid;
    }else if ([identifier isEqualToString:@"enc"]) {
        return [self securityTypeString:network];
    }else if ([identifier isEqualToString:@"rssi"]) {
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
    } else if ([network supportsSecurity:kCWSecurityWPAPersonal]) {
        return @"WPA-PSK";
    }else if ([network supportsSecurity:kCWSecurityWPAPersonalMixed]) {
        return @"WPA-PSK";
    }else if ([network supportsSecurity:kCWSecurityWPA2Personal]) {
        return @"WPA2-PSK";
    }else {
        return @"WPA";
    }
}

@end
