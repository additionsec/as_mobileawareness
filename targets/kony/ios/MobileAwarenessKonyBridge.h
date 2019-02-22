
#import <Foundation/Foundation.h>

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