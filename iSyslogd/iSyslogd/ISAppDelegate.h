//
//  ISAppDelegate.h
//  iSyslogd
//
//  Created by Curtis Jones on 2013.12.19.
//  Copyright (c) 2013 Curtis Jones. All rights reserved.
//

#import <Cocoa/Cocoa.h>

@interface ISAppDelegate : NSObject <NSApplicationDelegate>

@property (assign) IBOutlet NSWindow *window;
@property (readwrite, strong, nonatomic) IBOutlet NSTableView *firewallTableView;
@property (readwrite, strong, nonatomic) IBOutlet NSArrayController *firewallArrayController;

@end
