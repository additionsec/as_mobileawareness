
#import <Foundation/Foundation.h>

#include "as_mobileawareness.h"

// Kony specific header for function callback
#import "CallBack.h"

@interface MobileAwarenessKonyBridge : NSObject
+ (int)initialize:(CallBack*)cb;
+ (int)registerIdentity:(NSString*)identity;
+ (int)sendMessage:(uint32_t)msgid :(NSString*)data;
+ (long)heartbeat:(long)input;
+ (void)loginStatus:(Boolean)status;
+ (void)networkReachability;
+ (uint32_t)version;
+ (uint32_t)securityPosture;
@end




@implementation MobileAwarenessKonyBridge

static CallBack* _cb = NULL;
static Boolean initialized = false;
static int initialized_result = -1;

+ (NSString*)toHex:(NSData*)d
{
    NSMutableString* s1 = [NSMutableString stringWithCapacity:[d length]*2];
    const unsigned char *db = [d bytes];
    for (NSInteger idx=0; idx<[d length]; idx++){
        [s1 appendFormat:@"%02x", db[idx]];
    }
    return (NSString*)s1;
}

AS_CALLBACK(cb_proxy)
{
    if( _cb == NULL ) return;
    NSData *d1 = (__bridge NSData*)data1;
    NSData *d2 = (__bridge NSData*)data2;
    
    // For conveinence, we are going to stringify or hex encode everything prior to handing
    // it off to Javascript
    
    NSString *s1 = nil;
    NSString *s2 = nil;
    
    // Use the Messages Reference to know the various details/formats of data arguments:
    // http://addsec-cdn.s3-website-us-east-1.amazonaws.com/docs/ASMA_Messages/
    
    if( msgid == 8 ){
        if(d1 != NULL && d1 != nil) s1 = [MobileAwarenessKonyBridge toHex:d1];
        if(d2 != NULL && d2 != nil) s2 = [MobileAwarenessKonyBridge toHex:d2];
    }
    else if( msgid == 151 || msgid == 152 || msgid == 500 || msgid == 502 ){
        if(d1 != NULL && d1 != nil) s1 = [[NSString alloc] initWithData:d1 encoding:NSUTF8StringEncoding];
        if(d2 != NULL && d2 != nil) s2 = [MobileAwarenessKonyBridge toHex:d2];
    }
    else if( msgid == 316 || msgid == 404 || msgid == 407 || msgid == 408 || msgid == 413 ){
        if(d1 != NULL && d1 != nil) s1 = [MobileAwarenessKonyBridge toHex:d1];
        if(d2 != NULL && d2 != nil) s2 = [[NSString alloc] initWithData:d2 encoding:NSUTF8StringEncoding];
    }
    else {
        if(d1 != NULL && d1 != nil) s1 = [[NSString alloc] initWithData:d1 encoding:NSUTF8StringEncoding];
        if(d2 != NULL && d2 != nil) s2 = [[NSString alloc] initWithData:d2 encoding:NSUTF8StringEncoding];
    }
    
    [_cb executeWithArguments:[NSArray arrayWithObjects:@(msgid), @(msgsubid), s1, s2, nil] spawn:true];
}

+ (int)initialize:(CallBack*)cb
{
    // Do not initialize more than once
    if( initialized ) return initialized_result;
    
    // Use Identity For Vendor as the instance ID
	AS_UUID_DEFAULT_IDFV(devid);

    int res = -1;
    if( cb != NULL ){
        // Initialize with a callback
        _cb = cb;
	[_cb retain];
       res = AS_Initialize(devid, cb_proxy);
    } else {
        // Initialize without a callback
        res = AS_Initialize(devid, NULL);
    }
    
    // Save initialized results
    initialized_result = res;
    initialized = true;
    return res;
}


+ (int)registerIdentity:(NSString*)identity
{
    if( identity == NULL || identity == nil ) return -1;
    const char* ident = [identity UTF8String];
    if( ident == NULL ) return -1;
    return AS_Register_Identity(NULL);
}


+ (int)sendMessage:(uint32_t)msgid :(NSString*)data;
{
    if( data == NULL || data == nil ) return -1;
    const char* dat = [data UTF8String];
    if( dat == NULL ) return -1;
    return AS_Send_Message(msgid, dat);
}


+ (long)heartbeat:(long)input
{
    return AS_Heartbeat(input);
}


+ (void)loginStatus:(Boolean)status
{
    if( status )
        AS_Login_Status(1);
    else
        AS_Login_Status(0);
}


+ (void)networkReachability
{
    AS_Network_Reachability();
}


+ (uint32_t)version
{
    return AS_Version();
}


+ (uint32_t)securityPosture
{
    return AS_Security_Posture();
}

@end
