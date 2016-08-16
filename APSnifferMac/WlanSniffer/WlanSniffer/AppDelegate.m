//
//  AppDelegate.m
//  WlanSniffer
//
//  Created by sbxfc on 16/8/12.
//  Copyright © 2016年 me.rungame.sbxfc. All rights reserved.
//

#import "AppDelegate.h"
#import "APListView.h"

@interface AppDelegate ()
{
    APListView* apListView;
}

@property (weak) IBOutlet NSWindow *window;
@end

@implementation AppDelegate

- (void)applicationDidFinishLaunching:(NSNotification *)aNotification {
    // Insert code here to initialize your application
    
    apListView = [[APListView alloc] initWithFrame:[self.window.contentView bounds]];
    [self.window.contentView addSubview:apListView];
}

- (void)applicationWillTerminate:(NSNotification *)aNotification {
    // Insert code here to tear down your application
}

@end
