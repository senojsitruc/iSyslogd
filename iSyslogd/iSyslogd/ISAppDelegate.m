//
//  ISAppDelegate.m
//  iSyslogd
//
//  Created by Curtis Jones on 2013.12.19.
//  Copyright (c) 2013 Curtis Jones. All rights reserved.
//

#import "ISAppDelegate.h"
#import "ISUdpConnection.h"
#import <netdb.h>

@interface ISAppDelegate ()
{
	ISUdpConnection *_udpConnection;
	NSMutableArray *_lines;
	dispatch_queue_t _linesQueue;
	dispatch_queue_t _procQueue;
	dispatch_source_t _procSource;
	
	NSSound *_sound;
	NSMutableDictionary *_services;
	
	/**
	 * general parsing context
	 */
	NSUInteger _facility;
	NSUInteger _severity;
	NSDate *_timestamp;
	NSString *_processName;
	NSString *_processId;
	
	/**
	 * pf parsing context
	 */
	BOOL _pfPart1;
	NSString *_pfLine1;
	NSString *_pfLine2;
	NSString *_pfSrcAddr;
	NSString *_pfSrcPort;
	NSString *_pfDstAddr;
	NSString *_pfDstPort;
	NSString *_pfAction;
	NSString *_pfDirection;
	NSString *_pfInterface;
	NSString *_pfProto;
	NSString *_pfService;
}
@end

@implementation ISAppDelegate

- (void)applicationDidFinishLaunching:(NSNotification *)aNotification
{
	__unsafe_unretained typeof(self) _self = self;
	
	_lines = [[NSMutableArray alloc] init];
	_linesQueue = dispatch_queue_create("us.curtisjones.isyslgod.ISAppDelegate.linesQueue", DISPATCH_QUEUE_SERIAL);
	_sound = [NSSound soundNamed:@"Tink"];
	
	{
		_services = [[NSMutableDictionary alloc] init];
		
//	NSUInteger lastPort = 0;
//	NSUInteger wrapCount = 0;
		
		while (TRUE) {
			struct servent *s = getservent();
			
			if (s) {
				s->s_port = htons(s->s_port);
				
//			if (lastPort > s->s_port)
//				wrapCount += 1;
				
//			lastPort = s->s_port;
//			s->s_port += (wrapCount * 65536);
				
				[_services setValue:[NSString stringWithCString:s->s_name encoding:NSUTF8StringEncoding] forKey:[NSString stringWithFormat:@"%d-%s", s->s_port, s->s_proto]];
//			[_services setValue:[NSString stringWithCString:s->s_name encoding:NSUTF8StringEncoding] forKey:[NSString stringWithFormat:@"%d-%s", s->s_port/256, s->s_proto]];
			}
			else
				break;
		}
	}
	
	_udpConnection = [[ISUdpConnection alloc] init];
	_udpConnection.logLineHandler = ^ (NSString *addr, NSNumber *port, NSString *line) {
		dispatch_async(_self->_linesQueue, ^{
			[_self->_lines addObject:@{@"addr":addr, @"port":port, @"line":line}];
			dispatch_source_merge_data(_self->_procSource, 1);
		});
	};
	
	_procQueue = dispatch_queue_create("us.curtisjones.isyslogd.ISAppDelegate.procQueue", DISPATCH_QUEUE_SERIAL);
	_procSource = dispatch_source_create(DISPATCH_SOURCE_TYPE_DATA_ADD, 0, 0, _procQueue);
	dispatch_source_set_event_handler(_procSource, ^{ [_self procLines]; });
	
	dispatch_resume(_procSource);
}





//	2013-12-19 14:39:07.535 iSyslogd[19518:3903] -[ISAppDelegate procLines] [Line 61] handling line: {
//		addr = "10.12.79.1";
//		line = "<134>Dec 19 14:39:05 pf: 00:02:04.513354 rule 5/0(match): block in on em5: (tos 0x20, ttl 51, id 57853, offset 0, flags [DF], proto TCP (6), length 60)";
//		port = 514;
//	}
//	2013-12-19 14:39:07.535 iSyslogd[19518:3903] -[ISAppDelegate procLines] [Line 49]
//	2013-12-19 14:39:07.536 iSyslogd[19518:3903] -[ISAppDelegate procLines] [Line 61] handling line: {
//		addr = "10.12.79.1";
//		line = "<134>Dec 19 14:39:05 pf:     192.241.189.149.55867 > 10.1.10.10.22: Flags [S], cksum 0xa51f (correct), seq 30336679, win 14600, options [mss 1460,sackOK,TS val 220464986 ecr 0,nop,wscale 8], length 0";
//		port = 514;
//	}
//
//
//
//	2013-12-19 15:06:53.484 iSyslogd[19664:1003] -[ISAppDelegate procLines] [Line 76] handling line: {
//		addr = "10.12.79.1";
//		line = "<134>Dec 19 15:06:53 pf: 00:00:03.687212 rule 3/0(match): block in on em4: (hlim 255, next-header ICMPv6 (58) payload length: 32) fe80::189f:e760:ba4e:e053 > ff02::1: [icmp6 sum ok] ICMP6, neighbor advertisement, length 32, tgt is fe80::189f:e760:ba4e:e053, Flags [override]";
//		port = 514;
//	}
//	2013-12-19 15:06:53.484 iSyslogd[19664:1003] -[ISAppDelegate procLines] [Line 100]      severity=6, facility=16
//	2013-12-19 15:06:53.485 iSyslogd[19664:1003] -[ISAppDelegate procLines] [Line 121]      timestamp = 2013-12-19 20:06:53 +0000
//	2013-12-19 15:06:53.485 iSyslogd[19664:1003] -[ISAppDelegate procLines] [Line 61] -----------------------------------------------------------------------------------
//	2013-12-19 15:06:53.485 iSyslogd[19664:1003] -[ISAppDelegate procLines] [Line 76] handling line: {
//		addr = "10.12.79.1";
//		line = "<134>Dec 19 15:06:53 pf: \t  destination link-address option (2), length 8 (1): 10:9a:dd:82:bc:a5";
//		port = 514;
//	}
//	2013-12-19 15:06:53.486 iSyslogd[19664:1003] -[ISAppDelegate procLines] [Line 100]      severity=6, facility=16
//	2013-12-19 15:06:53.486 iSyslogd[19664:1003] -[ISAppDelegate procLines] [Line 121]      timestamp = 2013-12-19 20:06:53 +0000
//	2013-12-19 15:06:56.024 iSyslogd[19664:2007] -[ISAppDelegate procLines] [Line 61] -----------------------------------------------------------------------------------
//	2013-12-19 15:06:56.024 iSyslogd[19664:2007] -[ISAppDelegate procLines] [Line 76] handling line: {
//		addr = "10.12.79.1";
//		line = "<27>Dec 19 15:06:55 miniupnpd[6351]: sendto(udp_notify=12, 10.81.0.3): Host is down";
//		port = 514;
//	}
//
//
//
//	2013-12-19 19:59:24.141 iSyslogd[21155:1f27] -[ISAppDelegate procLines] [Line 119] -----------------------------------------------------------------------------------
//	2013-12-19 19:59:24.142 iSyslogd[21155:1f27] -[ISAppDelegate procLines] [Line 134] handling line: {
//		addr = "10.12.79.1";
//		line = "<134>Dec 19 19:59:23 pf: 00:02:52.729918 rule 5/0(match): block in on em5: (tos 0x20, ttl 103, id 256, offset 0, flags [none], proto TCP (6), length 40)";
//		port = 514;
//	}
//	2013-12-19 19:59:24.142 iSyslogd[21155:1f27] -[ISAppDelegate procLines] [Line 153]      severity=6, facility=16
//	2013-12-19 19:59:24.143 iSyslogd[21155:1f27] -[ISAppDelegate procLines] [Line 176]      timestamp = 2013-12-20 00:59:23 +0000
//	2013-12-19 19:59:24.143 iSyslogd[21155:1f27] -[ISAppDelegate procLines] [Line 205]      processName=pf, processId=6351
//	2013-12-19 19:59:24.143 iSyslogd[21155:1f27] -[ISAppDelegate procLines] [Line 119] -----------------------------------------------------------------------------------
//	2013-12-19 19:59:24.143 iSyslogd[21155:1f27] -[ISAppDelegate procLines] [Line 134] handling line: {
//		addr = "10.12.79.1";
//		line = "<134>Dec 19 19:59:23 pf:     117.41.184.34.6000 > 10.1.10.10.1433: Flags [S], cksum 0xd098 (correct), seq 1089077248, win 16384, length 0";
//		port = 514;
//	}
//	2013-12-19 19:59:24.144 iSyslogd[21155:1f27] -[ISAppDelegate procLines] [Line 153]      severity=6, facility=16
//	2013-12-19 19:59:24.144 iSyslogd[21155:1f27] -[ISAppDelegate procLines] [Line 176]      timestamp = 2013-12-20 00:59:23 +0000
//	2013-12-19 19:59:24.144 iSyslogd[21155:1f27] -[ISAppDelegate procLines] [Line 205]      processName=pf, processId=(null)
//	2013-12-19 19:59:24.144 iSyslogd[21155:1f27] -[ISAppDelegate handleLinePf:] [Line 272]      [AAA] line1: (null)
//	2013-12-19 19:59:24.144 iSyslogd[21155:1f27] -[ISAppDelegate handleLinePf:] [Line 273]      [AAA] line2: 117.41.184.34.6000 > 10.1.10.10.1433: Flags [S], cksum 0xd098 (correct), seq 1089077248, win 16384, length 0
//	2013-12-19 19:59:24.145 iSyslogd[21155:1f27] -[ISAppDelegate handleLinePf:] [Line 302]      srcAddr=117.41.184.34, srcPort=6000, dstAddr=10.1.10.10, dstPort=1433
//
//
//
//		line = "<134>Dec 19 14:39:05 pf: 00:02:04.513354 rule 5/0(match): block in on em5: (tos 0x20, ttl 51, id 57853, offset 0, flags [DF], proto TCP (6), length 60)";
//		line = "<134>Dec 19 14:39:05 pf:     192.241.189.149.55867 > 10.1.10.10.22: Flags [S], cksum 0xa51f (correct), seq 30336679, win 14600, options [mss 1460,sackOK,TS val 220464986 ecr 0,nop,wscale 8], length 0";
//		line = "<134>Dec 19 15:06:53 pf: 00:00:03.687212 rule 3/0(match): block in on em4: (hlim 255, next-header ICMPv6 (58) payload length: 32) fe80::189f:e760:ba4e:e053 > ff02::1: [icmp6 sum ok] ICMP6, neighbor advertisement, length 32, tgt is fe80::189f:e760:ba4e:e053, Flags [override]";
//		line = "<134>Dec 19 15:06:53 pf: \t  destination link-address option (2), length 8 (1): 10:9a:dd:82:bc:a5";
//		line = "<27>Dec 19 15:06:55 miniupnpd[6351]: sendto(udp_notify=12, 10.81.0.3): Host is down";

- (void)procLines
{
	DLog(@"-----------------------------------------------------------------------------------");
	
	__block NSDictionary *entry = nil;
	__block NSUInteger count = 0;
	
	dispatch_sync(_linesQueue, ^{
		if (nil != (entry = [_lines firstObject])) {
			[_lines removeObjectAtIndex:0];
			count = _lines.count;
		}
	});
	
	if (count)
		dispatch_source_merge_data(_procSource, 1);
	
	DLog(@"handling line: %@", entry);
	
	NSString *line = entry[@"line"];
	
	// "<XX>"
	{
		NSRange lt, gt;
		
		lt = [line rangeOfString:@"<"];
		gt = [line rangeOfString:@">"];
		
		if (NSNotFound == lt.location || NSNotFound == gt.location)
			return;
		
		NSUInteger props = [line substringWithRange:NSMakeRange(lt.location+1, gt.location-lt.location-1)].integerValue;
		
		_severity = (props & 0x7);
		_facility = (props & 0xF8) >> 3;
		
		DLog(@"     severity=%d, facility=%d", (int)_severity, (int)_facility);
		
		line = [line substringFromIndex:gt.location + 1];
	}
	
	// "Dec 19 14:39:05 "
	{
		NSArray *parts, *time;
		NSCalendar *calendar = [NSCalendar currentCalendar];
		NSDateComponents *dc = [[NSDateComponents alloc] init];
		
		parts = [line componentsSeparatedByString:@" "];
		time = [(NSString *)parts[2] componentsSeparatedByString:@":"];
		
		dc.day = ((NSString *)parts[1]).integerValue;
		dc.year = [self currentYear];
		dc.hour = ((NSString *)time[0]).integerValue;
		dc.minute = ((NSString *)time[1]).integerValue;
		dc.second = ((NSString *)time[2]).integerValue;
		dc.month = [self monthWithAbbreviation:parts[0]];
		
		_timestamp = [calendar dateFromComponents:dc];
		
		DLog(@"     timestamp = %@", _timestamp);
		
		line = [line substringFromIndex:16];
	}
	
	// "pf: "
	// "miniupnpd[6351]: "
	// "kernel: "
	// "php: "
	// "sshlockout[76117]: "
	{
		NSRange colonSpaceRange, openSbRange, closeSbRange;
		
		colonSpaceRange = [line rangeOfString:@": "];
		
		if (NSNotFound == colonSpaceRange.location)
			return;
		
		openSbRange = [line rangeOfString:@"[" options:0 range:NSMakeRange(0, colonSpaceRange.location)];
		closeSbRange = [line rangeOfString:@"]" options:0 range:NSMakeRange(0, colonSpaceRange.location)];
		
		if (NSNotFound != openSbRange.location && NSNotFound != closeSbRange.location) {
			_processName = [line substringToIndex:openSbRange.location - 1];
			_processId = [line substringWithRange:NSMakeRange(openSbRange.location + 1, closeSbRange.location - openSbRange.location - 1)];
		}
		else {
			_processName = [line substringToIndex:colonSpaceRange.location];
		}
		
		DLog(@"     processName=%@, processId=%@", _processName, _processId);
		
		line = [line substringFromIndex:colonSpaceRange.location + 1 + 1];
	}
	
	if ([_processName isEqualToString:@"pf"]) {
		[self handleLinePf:line];
	}
	else if ([_processName isEqualToString:@"racoon"]) {
		
	}
	else if ([_processName isEqualToString:@"miniupnpd"]) {
		
	}
	else if ([_processName isEqualToString:@"kernel"]) {
		
	}
	else if ([_processName isEqualToString:@"php"]) {
		
	}
	else if ([_processName isEqualToString:@"sshlockout"]) {
		
	}
}

/**
 * "<134>Dec 19 14:39:05 pf: 00:02:04.513354 rule 5/0(match): block in on em5: (tos 0x20, ttl 51, id 57853, offset 0, flags [DF], proto TCP (6), length 60)";
 * "<134>Dec 19 14:39:05 pf:     192.241.189.149.55867 > 10.1.10.10.22: Flags [S], cksum 0xa51f (correct), seq 30336679, win 14600, options [mss 1460,sackOK,TS val 220464986 ecr 0,nop,wscale 8], length 0";
 *
 * "00:02:04.513354 rule 5/0(match): block in on em5: (tos 0x20, ttl 51, id 57853, offset 0, flags [DF], proto TCP (6), length 60)";
 * "    192.241.189.149.55867 > 10.1.10.10.22: Flags [S], cksum 0xa51f (correct), seq 30336679, win 14600, options [mss 1460,sackOK,TS val 220464986 ecr 0,nop,wscale 8], length 0";
 *
 */
- (void)handleLinePf:(NSString *)line
{
	// "00:02:04.513354 rule 5/0(match): block in on em5: (tos 0x20, ttl 51, id 57853, offset 0, flags [DF], proto TCP (6), length 60)";
	if (FALSE == _pfPart1) {
		if ([line hasPrefix:@"\t  "])
			return;
		
		_pfLine1 = line;
		_pfPart1 = TRUE;
		
		NSRange colonSpaceRange;
		NSString *stringPart1=nil, *stringPart2=nil;
		NSArray *parts = nil;
		
		// "00:02:04.513354 rule 5/0(match)"
		colonSpaceRange = [line rangeOfString:@": "];
		stringPart1 = [line substringToIndex:colonSpaceRange.location];
		line = [line substringFromIndex:colonSpaceRange.location + 2];
		
		// "block in on em5"
		colonSpaceRange = [line rangeOfString:@": "];
		stringPart2 = [line substringToIndex:colonSpaceRange.location];
		line = [line substringFromIndex:colonSpaceRange.location + 2];
		
		parts = [stringPart2 componentsSeparatedByString:@" "];
		_pfAction = parts[0];    // "block" or "pass"
		_pfDirection = parts[1]; // "in" or "out" (?)
		_pfInterface = parts[3]; // "em5", "em4", etc.
		
		// "(tos 0x20, ttl 51, id 57853, offset 0, flags [DF], proto TCP (6), length 60)"
		parts = [[line substringWithRange:NSMakeRange(1,line.length-3)] componentsSeparatedByString:@", "];
		[parts enumerateObjectsUsingBlock:^ (NSString *part, NSUInteger index, BOOL *stop) {
			if ([part hasPrefix:@"proto "]) {
				_pfProto = [part substringFromIndex:6].lowercaseString;
				NSRange spaceRange = [_pfProto rangeOfString:@" "];
				if (NSNotFound != spaceRange.location)
					_pfProto = [_pfProto substringToIndex:spaceRange.location];
			}
		}];
		
		return;
	}
	
	// "    192.241.189.149.55867 > 10.1.10.10.22: Flags [S], cksum 0xa51f (correct), seq 30336679, win 14600, options [mss 1460,sackOK,TS val 220464986 ecr 0,nop,wscale 8], length 0";
	// "    181.119.18.49.5060 > 10.1.10.10.5060: SIP, length: 405"
	if ([line hasPrefix:@"    "]) {
		_pfLine2 = line = [line substringFromIndex:4];
		
		DLog(@"     [AAA] line1: %@", _pfLine1);
		DLog(@"     [AAA] line2: %@", _pfLine2);
		
		NSRange addrsRange;
		NSRange gtRange;
		NSRange lastDot1, lastDot2;
		NSString *addrPort1=nil, *addrPort2=nil;
		
		addrsRange = [line rangeOfString:@": "];
		gtRange = [line rangeOfString:@" > " options:0 range:NSMakeRange(0., addrsRange.location)];
		
		addrPort1 = [line substringToIndex:gtRange.location];
		addrPort2 = [line substringWithRange:NSMakeRange((gtRange.location+gtRange.length), (addrsRange.location-gtRange.location-gtRange.length))];
		
		lastDot1 = [addrPort1 rangeOfString:@"." options:NSBackwardsSearch];
		lastDot2 = [addrPort2 rangeOfString:@"." options:NSBackwardsSearch];
		
		_pfSrcAddr = [addrPort1 substringToIndex:lastDot1.location];
		_pfSrcPort = [addrPort1 substringFromIndex:lastDot1.location + 1];
		
		_pfDstAddr = [addrPort2 substringToIndex:lastDot2.location];
		_pfDstPort = [addrPort2 substringFromIndex:lastDot2.location + 1];
		
		if (_pfDstPort && _pfProto)
			_pfService = _services[[NSString stringWithFormat:@"%@-%@", _pfDstPort, _pfProto]];
		
		line = [line substringFromIndex:addrsRange.location + 2];
		
		if ([line hasPrefix:@"SIP"])
			return;
		
		_pfPart1 = FALSE;
		
		DLog(@"     srcAddr=%@, srcPort=%@, dstAddr=%@, dstPort=%@", _pfSrcAddr, _pfSrcPort, _pfDstAddr, _pfDstPort);
	}
	
	// "\t  destination link-address option (2), length 8 (1): 10:9a:dd:82:bc:a5"
	else if ([line hasPrefix:@"\t  "]) {
		_pfLine2 = line = [line substringFromIndex:3];
		_pfPart1 = FALSE;
		
		if ([line hasPrefix:@"destination link-address "]) {
			NSRange lastSpaceRange = [line rangeOfString:@" " options:NSBackwardsSearch];
			_pfDstAddr = [line substringFromIndex:lastSpaceRange.location + 1];
		}
		
		DLog(@"     [BBB] dstAddr=%@", _pfDstAddr);
	}
	
	else if ([line hasPrefix:@"\t"]) {
		DLog(@"     [CCC] line=%@", line);
		return;
	}
	
	if (_pfSrcAddr && _pfSrcPort && FALSE == [_pfSrcAddr hasPrefix:@"10."]) {
		NSMutableDictionary *entry = [[NSMutableDictionary alloc] init];
		NSUInteger units = NSYearCalendarUnit | NSMonthCalendarUnit | NSDayCalendarUnit | NSHourCalendarUnit | NSMinuteCalendarUnit | NSSecondCalendarUnit | NSTimeZoneCalendarUnit;
		NSDateComponents *dc = [[NSCalendar currentCalendar] components:units fromDate:_timestamp];
		NSString *timestamp = [NSString stringWithFormat:@"%04lu.%02lu.%02lu %02lu:%02lu:%02lu",
													 dc.year, dc.month, dc.day, dc.hour, dc.minute, dc.second];
		
		[entry setValue:_pfAction forKey:@"action"];
		[entry setValue:timestamp forKey:@"timestamp"];
		[entry setValue:_pfInterface forKey:@"interface"];
		
		if (_pfSrcAddr)
			[entry setValue:[NSString stringWithFormat:@"%@:%@", _pfSrcAddr, _pfSrcPort] forKey:@"source"];
		
		if (_pfDstAddr && _pfDstPort && _pfService)
			[entry setValue:[NSString stringWithFormat:@"%@:%@ (%@)", _pfDstAddr, _pfDstPort, _pfService] forKey:@"destination"];
		else if (_pfDstAddr && _pfDstPort)
			[entry setValue:[NSString stringWithFormat:@"%@:%@", _pfDstAddr, _pfDstPort] forKey:@"destination"];
		else if (_pfDstAddr)
			[entry setValue:_pfDstAddr forKey:@"destination"];
		
		[entry setValue:_pfProto forKey:@"protocol"];
		
		dispatch_async(dispatch_get_main_queue(), ^{
			[_firewallArrayController addObject:entry];
			[_sound play];
		});
	}
	
	_facility = 0;
	_severity = 0;
	_timestamp = nil;
	_processName = nil;
	_processId = nil;
	
	_pfSrcAddr = nil;
	_pfSrcPort = nil;
	_pfDstAddr = nil;
	_pfDstPort = nil;
	
	_pfAction = nil;
	_pfDirection = nil;
	_pfInterface = nil;
	_pfProto = nil;
	
	_pfLine1 = nil;
	_pfLine2 = nil;
}





- (NSUInteger)currentYear
{
	return [[NSCalendar currentCalendar] component:NSYearCalendarUnit fromDate:(NSDate *)[NSDate date]];
}

- (NSUInteger)monthWithAbbreviation:(NSString *)month
{
	if ([month isEqualToString:@"Jan"])
		return 1;
	else if ([month isEqualToString:@"Feb"])
		return 2;
	else if ([month isEqualToString:@"Mar"])
		return 3;
	else if ([month isEqualToString:@"Apr"])
		return 4;
	else if ([month isEqualToString:@"May"])
		return 5;
	else if ([month isEqualToString:@"Jun"])
		return 6;
	else if ([month isEqualToString:@"Jul"])
		return 7;
	else if ([month isEqualToString:@"Aug"])
		return 8;
	else if ([month isEqualToString:@"Sep"])
		return 9;
	else if ([month isEqualToString:@"Oct"])
		return 10;
	else if ([month isEqualToString:@"Nov"])
		return 11;
	else if ([month isEqualToString:@"Dec"])
		return 12;
	else
		return 0;
}

@end
