//
//  Callback.m
//  Copyright © 2016 additionsecurity.com. All rights reserved.
//

#import <Foundation/Foundation.h>

#include "as_mobileawareness.h"


AS_CALLBACK(my_callback)
{
    // AS_CALLBACK function definition:
    // void nom(int msgid, int msgsubid, CFDataRef data1, CFDataRef data2)
    
    
    //
    // Bridge the CFDataRef to more friendly NSData
    // CAUTION: either of these values may be null
    //
    NSData *d1 = (__bridge NSData*)data1;
    NSData *d2 = (__bridge NSData*)data2;
    
    
    //
    // Indication that the initial security scan is complete
    //
    if( msgid == 50 )      // 50: Initialization Complete
    {
        // The basic security information has been reported; at this point
        // you can make go/no-go security decisions based on what was
        // previously reported.
        
        // ... Your logic ...
        NSLog(@"SECURITY: INITCOMPLETED");        
    }
    
    //
    // Malware on the device
    //
    if( msgid == 150       // 150: Known Malware Artifact Detected
       || msgid == 152    // 152: Known Malware Signer Present
       )
    {
        // ... Your response ...
        NSLog(@"SECURITY: MALWARE");
    }


    //
    // Simulator/Emulator detection
    //
    if( msgid == 300        // 300: Synthetic System (Emulator/Simulator)
       )
    {
        // NOTE: this will only appear in explicit simulator builds; IOS generally does not
        // have any known generally-viable ARM binary emulators in the wild
        
        // ... Your response ...
        NSLog(@"SECURITY: SIMULATOR");
    }
    
    //
    // Jailbreak detection
    //
    if( msgid == 305       // 305: Privilege Providing Application (SU, etc.)
       || msgid == 314    // 314: System Rooted/Jailbroken
       )
    {
        // ... Your response ...
        NSLog(@"SECURITY: ROOTED/JAILBROKEN");
    }
    
    
    //
    // Hacking tools, exploits, and anti-jailbreak tools
    //
    if( msgid == 307       // 307: Hacking Tool Installed
       || msgid == 308    // 308: Security Subversion Tool Installed (rooting/jailbreak exploit)
       || msgid == 315    // 315: Security Hiding Tool Installed (trying to hide root/jailbreak)
       )
    {
        // ... Your response ...
        NSLog(@"SECURITY: SECURITY TOOL/EXPLOIT");
    }
    
    //
    // Application tampering, game cheat, or in-app-purchase fraud tool
    //
    if( msgid == 309       // 309: Application Tampering Tool Installed
       || msgid == 310    // 310: Game Cheat Tool Installed
       || msgid == 311    // 311: In-App Purchasing Fraud Tool Installed
       )
    {
        // ... Your response ...
        NSLog(@"SECURITY: CHEAT/FRAUD/TAMPER TOOL");
    }
    

    //
    // Sandbox and system security issues
    //
    if( msgid == 313       // 313: Security Expectation Failure (sandbox security is broken)
       || msgid == 411    // 411: Security Operation Failure (system security call failed)
       )
    {
        // ... Your response ...
        NSLog(@"SECURITY: RUNTIME OPERATION VIOLATION");
    }
    
    //
    // Debugger detection
    //
    if( msgid == 400       // 400: Debugger/Instrumentation Artifact
       )
    {
        // NOTE: this item may indicate a debugger has been detected, or the app has
        // specifically been configured to allow debugging
        
        // ... Your response ...
        NSLog(@"SECURITY: DEBUGGER");
    }
    
    //
    // Application tampering detected
    //
    if( msgid == 401       // 401: Application Tampering Detected
       || msgid == 406    // 406: Stealth Callback Failure (Advanced MobileAwareness feature)
       || msgid == 416    // 416: Heartbeat failure (re: heartbeat() API call)
       )
    {
        // ... Your response ...
        NSLog(@"SECURITY: RUNTIME APP TAMPERING/INTEGRITY VIOLATION");
    }
    

    //
    // Network man-in-the-middle detection
    //
    if( msgid == 500       // 500: SSL Pin Violation (network MitM attacker detected)
       )
    {
        // ... Your response ...
        NSLog(@"SECURITY: NETWORK ATTACKER");
    }
    
    
    //
    // Measurement to detect binary modification
    //
    if( msgid == 407 )     // 407: Application Measurement
    {
        // This message includes the SHA1 hash of the application bundle.
        //
        // You can test the values against expectations to see if your application has been modified.
        
        // NOTE: The measurement value can change in various circumstances:
        // - Application was resigned (legitimately by Apple App Store or other)
        // - Apple App Store generated a device-specific bitcode build
        
        // Since Apple App Store will change the binary, and thus the hash will change upon store
        // release, you cannot know ahead of time what the final known-good hash value will be.  Instead,
        // once your app is rebuilt and resigned by Apple, you can runtime collect those hashes into
        // a known-good whitelist, host them on a web service, and have your app dynamically download and compare
        // for violations.  You cannot hard-code the expected hash values into the binary itself, since the mere
        // act of adding the existing hash will change the hash.  You can store the known good hashes in a plist
        // or other external file, but you still are subject to Apple's modifications which won't be known until
        // Apple makes the final modifications (App Store signing, bitcode recompiling).
        
        // If this sounds complicated, it's because it is complicated.  It is notably easier to rely on
        // signer verification (see below) than binary measurement to detect modification, since an attacker
        // would have to resign the binary after they modify it for a normal device to allow it.  Known valid
        // signers are predictable ahead of time, making the creation of a whitelist an easier effort.
        
        if( msgsubid == 1 ) // 1: Application executable file
        {
            // data1: SHA1 hash byte array (binary, 20 bytes) of the file
            // data2: string of the file name/path on device
            
            // ... Your logic ...
            if( d1 != NULL ){
                NSLog(@"SECURITY: EXECUTABLE MEASUREMENT=%@", [d1 description]);
            }            
        }
    }
    
    //
    // Embedded Provisioning Signer
    //
    if( msgid == 408 ){ // 408: Provisioning Signer
        // data1: SHA1 hash (binary bytes)
        // data2: Certificate subject
        //
        // You can test the values against expectations to see if your application was given a new
        // provisioning profile (Developer, Ad-hoc, Enterprise Distribution, or App Store).
        
        NSString *hash = @"(Unknown)";
        NSString *signer = @"(Unknown)";
        if( d1 != NULL ) hash = [d1 description];
        if( d2 != NULL ) signer = [[NSString alloc] initWithData:d2 encoding:NSUTF8StringEncoding];
        NSLog(@"SECURITY: PROVISIONING SIGNER HASH=%@ SUBJECT=%@", hash, signer);
    }

    //
    // Application Signer
    //
    if( msgid == 404 ){  // 404: Application Signer
        // data1: SHA1 hash (binary bytes)
        // data2: Certificate subject
        //
        // You can test the values against expectations to see if your application was given a new
        // provisioning profile (Developer, Ad-hoc, Enterprise Distribution, or App Store).
        
        NSString *hash = @"(Unknown)";
        NSString *signer = @"(Unknown)";
        if( d1 != NULL ) hash = [d1 description];
        if( d2 != NULL ) signer = [[NSString alloc] initWithData:d2 encoding:NSUTF8StringEncoding];
        NSLog(@"SECURITY: APPLICATION SIGNER HASH=%@ SUBJECT=%@", hash, signer);
    }

    
}