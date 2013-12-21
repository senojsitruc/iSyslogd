//
//  ISUdpConnection.h
//  iSyslogd
//
//  Created by Curtis Jones on 2013.12.19.
//  Copyright (c) 2013 Curtis Jones. All rights reserved.
//

#import <Foundation/Foundation.h>

typedef void (^ISUdpConnectionLogLineHandler) (NSString *addr, NSNumber *port, NSString *logline);

@interface ISUdpConnection : NSObject

@property (readwrite, strong, nonatomic) ISUdpConnectionLogLineHandler logLineHandler;

@end
