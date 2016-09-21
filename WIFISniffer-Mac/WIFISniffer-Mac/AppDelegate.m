//
//  AppDelegate.m
//  WIFISniffer-Mac
//
//  Created by sbxfc on 16/9/9.
//  Copyright © 2016年 me.rungame.sbxfc. All rights reserved.
//

#import "AppDelegate.h"
#import "WIFIListViewController.h"

@interface AppDelegate ()
{

}

//@property (weak) IBOutlet NSWindow *window;
@end

@implementation AppDelegate

- (void)applicationDidFinishLaunching:(NSNotification *)aNotification {
    // Insert code here to initialize your application
    
    _mainWindow = [[WIFIListViewController alloc] initWithWindowNibName:@"WIFIListViewController"];
    [[_mainWindow window] center];
    [[_mainWindow window] orderFront:nil];
}

- (void)applicationWillTerminate:(NSNotification *)aNotification {
    // Insert code here to tear down your application
}

@end
