//
//  WIFISniffer.m
//  WIFISniffer-Mac
//
//  Created by sbxfc on 16/9/12.
//  Copyright © 2016年 me.rungame.sbxfc. All rights reserved.
//

#import "WIFISniffer.h"
#import "IEEE_80211_Packet.h"
#import <CoreWLAN/CoreWLAN.h>
#import <pcap.h>

#define IP_PKT_MAX_LEN 65535

@interface WIFISniffer()
{
    CWInterface* interface;/*无线网接口*/
    pcap_t* pcap;
    NSThread * pThread;
    NSLock * channelLock;
    CWChannel * hopChannel;
}

@end

@implementation WIFISniffer

@synthesize delegate;

-(instancetype)init
{
    if ((self = [super init])) {
        interface = [CWWiFiClient sharedWiFiClient].interface;
        if(interface){
            [interface disassociate];
            
            char errbuf[PCAP_ERRBUF_SIZE];
            
            /*打开一个无线网口抓取IP数据包。*/
            pcap = pcap_open_live([interface.interfaceName UTF8String],IP_PKT_MAX_LEN,1/*混杂模式*/,1/*等待时间(ms)*/,errbuf);
            pcap_set_datalink(pcap, DLT_IEEE802_11_RADIO);
        }
    }
    return self;
}

#pragma mark Fetch Package

- (void)setChannel:(CWChannel *)channel {
    [channelLock lock];
    hopChannel = channel;
    [channelLock unlock];
}

/**
 *  开始抓包
 */
-(void)start{
    if(pThread)return;
    
    pThread = [[NSThread alloc] initWithTarget:self selector:@selector(fetchOnThread) object:nil];
    [pThread start];
}

- (BOOL)setChannel1:(NSInteger)channel {
    [interface disassociate];
    NSSet * channels = [interface supportedWLANChannels];
    for (CWChannel * channelObj in channels) {
        if ([channelObj channelNumber] == channel) {
            return [interface setWLANChannel:channelObj error:nil];
        }
    }
    return NO;
}

-(void)fetchOnThread{
    
    @autoreleasepool {
        while (true) {
            
            if ([[NSThread currentThread] isCancelled]) {
                [self closePcap];
                return;
            }
            
            [channelLock lock];
            if (hopChannel) {
                [self setChannel1:hopChannel.channelNumber];
                hopChannel = nil;
            }
            [channelLock unlock];
            
            IEEE_80211_Packet * packet = nil;
            @try {
                packet = [self fetchPKT];
            } @catch (NSException * exception) {
                [self closePcap];
                return;
            }
            
            if ([[NSThread currentThread] isCancelled]) {
                [self stopThread];
                return;
            }
            
            if(packet){
                [self wifiSnifferGotPackageDelegate:packet];
            }

            if(!packet){;
                usleep(5000);
            }
        }
    }
}

/**
 *  抓取一个数据包
 */
-(IEEE_80211_Packet*)fetchPKT{
   
    struct pcap_pkthdr * header;
    const u_char * pkt;
    int ret = pcap_next_ex(pcap,&header,&pkt);
    if(ret < 0){
        const char * error = pcap_geterr(pcap);
        @throw [NSException exceptionWithName:@"libpcap"
                                       reason:[NSString stringWithUTF8String:error]
                                     userInfo:nil];
    }
    
    /*抓包成功!*/
    if (ret == 1) {
        uint16_t * words = (uint16_t *)pkt;
        if (words[1] >= header->caplen) return nil;
        
        const u_char * dataBuffer = pkt + words[1];
        uint32_t len = header->caplen - words[1];
        NSData * data = [NSData dataWithBytes:dataBuffer length:len];
        IEEE_80211_Packet * result = [[IEEE_80211_Packet alloc] initWithData:data];
        result.rssi = getRadiotapRSSI(pkt);
        return result;
    }
    
    return nil;
}

#pragma mark WIFISiniffer Delegate

/**
 *  抓包错误
 */
- (void)wifiSnifferErrorDelegate:(NSError *)error {
    if (![[NSThread currentThread] isMainThread]) {
        [self performSelectorOnMainThread:@selector(wifiSnifferErrorDelegate:) withObject:error waitUntilDone:NO];
        return;
    }
    
    if ([self.delegate respondsToSelector:@selector(wifiSniffer:failedWithError:)]) {
        [self.delegate wifiSniffer:self failedWithError:error];
    }
}

/**
 *  抓包成功
 *
 */
- (void)wifiSnifferGotPackageDelegate:(IEEE_80211_Packet *)packet {
    if (![[NSThread currentThread] isMainThread]) {
        [self performSelectorOnMainThread:@selector(wifiSnifferGotPackageDelegate:) withObject:packet waitUntilDone:NO];
        return;
    }
    if ([self.delegate respondsToSelector:@selector(wifiSniffer:gotPacket:)]) {
        [self.delegate wifiSniffer:self gotPacket:packet];
    }
}


/**
 *  从Radiotap部分获取RSSI的值
 */
static int getRadiotapRSSI(const u_char * packet) {
    u_char present = packet[4];
    if (!(present & 0x20)) {
        return 6;
    }
    size_t fieldOffset = 0;
    if (present & 1) {
        fieldOffset += 8;
    }
    if (present & 2) {
        fieldOffset += 1;
    }
    if (present & 4) {
        fieldOffset += 1;
    }
    if (present & 8) {
        if (fieldOffset & 1) {
            fieldOffset++;
        }
        fieldOffset += 4;
    }
    if (present & 0x10) {
        if (fieldOffset & 1) {
            fieldOffset++;
        }
        fieldOffset += 2;
    }
    
    return (int)((char *)packet)[8+fieldOffset];
}

/*关闭pcap监听*/
-(void)closePcap
{
    if(pcap){
        pcap_close(pcap);
        pcap = NULL;
    }
}

/*关闭线程*/
-(void) stopThread
{
    if(pThread){
        [pThread cancel];
        pThread = nil;
    }
}

-(void)dealloc{
    [self stopThread];
    [self closePcap];
}

@end
