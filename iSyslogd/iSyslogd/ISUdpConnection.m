//
//  ISUdpConnection.m
//  iSyslogd
//
//  Created by Curtis Jones on 2013.12.19.
//  Copyright (c) 2013 Curtis Jones. All rights reserved.
//

#import "ISUdpConnection.h"

#import <errno.h>
#import <fcntl.h>
#import <netdb.h>
#import <pthread.h>
#import <signal.h>
#import <stdint.h>
#import <stdio.h>
#import <stdlib.h>
#import <string.h>
#import <strings.h>
#import <unistd.h>
#import <time.h>
#import <arpa/inet.h>
#import <netinet/tcp.h>
#import <sys/ioctl.h>
#import <sys/select.h>
#import <sys/socket.h>
#import <sys/time.h>

@interface ISUdpConnection ()
{
	dispatch_queue_t _queue;
	dispatch_source_t _source;
	
	int _sock;
	uint16_t _port;
	struct sockaddr_in _addr;
	unsigned char _buff[16000];
}
@end

@implementation ISUdpConnection

- (id)init
{
	self = [super init];
	
	if (self) {
		_port = 10514;
		_queue = dispatch_queue_create("us.curtisjones.isyslogd.ISUdpConnection", DISPATCH_QUEUE_SERIAL);
		
		int sock, reuse=1 /*, nodelay=1*/ ;
		struct sockaddr_in soaddr;
		__unsafe_unretained __typeof(self) _self = self;
		
		// create the socket
		if (-1 == (sock = socket(AF_INET, SOCK_DGRAM, 0))) {
			DLog("failed to socket(), %s\n", strerror(errno));
			return nil;
		}
		
		// make the socket reuseable
		if (0 != setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse))) {
			DLog("failed to setsockopt(SO_REUSEADDR), %s\n", strerror(errno));
			return nil;
		}
		
		memset(&soaddr, 0, sizeof(soaddr));
		soaddr.sin_family = AF_INET;
		soaddr.sin_port = htons(_port);
		soaddr.sin_addr.s_addr = htonl(INADDR_ANY);
		
		// bind to the local port
		if (-1 == bind(sock, (struct sockaddr *)&soaddr, sizeof(soaddr))) {
			DLog("failed to bind(), %s\n", strerror(errno));
			return nil;
		}
		
		_sock = sock;
		_source = dispatch_source_create(DISPATCH_SOURCE_TYPE_READ, _sock, 0, _queue);
		
		dispatch_source_set_event_handler(_source, ^{ [_self handleSourceEvent]; });
		dispatch_resume(_source);
		
		DLog(@"ready");
	}
	
	return self;
}

- (void)handleSourceEvent
{
	struct sockaddr_in addr;
	uint16_t port = 0;
	char addrstr[INET6_ADDRSTRLEN] = { 0 };
	socklen_t addrlen = sizeof(struct sockaddr_in);
	ssize_t bytes = recvfrom(_sock, _buff, 16000, 0, (struct sockaddr *)&addr, &addrlen);
	
	_buff[bytes] = '\0';
	port = ntohs(addr.sin_port);
	inet_ntop(addr.sin_family, &addr.sin_addr, addrstr, INET6_ADDRSTRLEN);
	
	//DLog(@"received %04d bytes [%s:%d]: %s", (int)bytes, addrstr, (int)port, _buff);
	
	NSString *logline = [[NSString alloc] initWithCString:(const char *)_buff encoding:NSUTF8StringEncoding];
	NSString *ipaddr = [[NSString alloc] initWithCString:(const char *)addrstr encoding:NSUTF8StringEncoding];
	
	if (_logLineHandler)
		_logLineHandler(ipaddr, @(port), logline);
}

@end
