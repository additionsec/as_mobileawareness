//
// Addition Security MobileAwareness SDK for Kony
// Copyright 2016 Addition Security Inc. All Rights Reserved.
//

// DEVELOPERS: You have two places to potentially edit code in this file:
// 1. In MobileAwareness_init(), to choose whether or not to use a callback
// 2. In MobileAwareness_callback(), if you want to use callback to respond to events

//
// MobileAwareness_init() - initialize the security library
//
function MobileAwareness_init()
{
	// CHOICE:
	// - Initialize with callback, and handle security events in callback; or
	// - Initialize without a callback, and use polling-based queries to get results

	// WITH CALLBACK:
	var res = MobileAwareness_init_internal(MobileAwareness_callback);
	// WITHOUT CALLBACK:
	//var res = MobileAwareness_init_internal(null);

	// HANDLE ERROR:
	if( res != 0 ){
		// For debugging:
		kony.print("ERROR - MobileAwareness did not initialize correctly");

		if( res == -2 ){
			// License issue (expired, not licensed for this app, etc.)
			// ... TODO: put your error handling code here
		}
		else if( res == -3 ){
			// Security issue -- internal tampering detected
			// ... TODO: put your error handling code here	
		}
		else {
			// General/unspecified internal error
			// ... TODO: put your error handling code here
		}
	}
}

//
// MobileAwareness_callback - asynchronous callback to receive realtime security events
//

// Production builds should set DEBUG=false, to prevent any inappropriate print statements
// from being shown in your production app.  Debug builds can use DEBUG=true for visibility.
var DEBUG=true;

function MobileAwareness_callback(msgid, msgsubid, data1, data2)
{
		// msgid, msgsubid = integer

		if(DEBUG) kony.print("AS_CALLBACK - " + msgid.toString() + "/" + msgsubid.toString());
								
		// Data1/data2 are either null, or contain strings.  The contents of the
		// strings are contextual to which callback (msgid).
								
		//
        // Indication that the initial security scan is complete
        //
        if( msgid == 50 )      // 50: Initialization Complete
        {
            // The basic security information has been reported; at this point
            // you can make go/no-go security decisions based on what was
            // previously reported.

            // ... Your logic ...
        }


        //
        // Malware on the device
        //
        if( msgid == 150       // 150: Known Malware Artifact Detected
                || msgid == 152    // 152: Known Malware Signer Present
                )
        {
            // ... Your response ...
            if(DEBUG) kony.print("SECURITY: MALWARE");
        }

        //
        // Application vulnerabilities
        //
        if( msgid == 252       // 252: Open Application Local Attack Vector
                || msgid == 253    // 253: Open Application Remote Attack Vector
                )
        {
            // These are likely items you would want to address before you ship
            // to production, as they represent open vulnerabilities.  For example,
            // debug is enabled in your manifest.

            // ... Your response ...
            if(DEBUG) kony.print("SECURITY: APP VULNERABILITY");
        }

        if( msgid == 300        // 300: Synthetic System (Emulator/Simulator)
                )
        {
            // ... Your response ...
            if(DEBUG) kony.print("SECURITY: EMULATOR");
        }

        if( msgid == 302       // 302: Non-Production System
                || msgid == 317    // 317: System Unsigned (Android)
                )
        {
            // WARNING: unfortunately there are Android vendors that ship devices that don't
            // meet Google's requirements for production, e.g. debug builds, signed with test
            // keys, etc.  These are effectively development builds that got sent to market,
            // and are indistinguishable from development builds that a hacker may make to
            // try to compromise an app.  Most users don't know they purchased an at-risk
            // development grade device/firmware build, and are in no position to really
            // remedy it except for buy a new device.  Therefore, you should consider using
            // this category of indicators passively if you do not want to snag a few
            // innocent users who unfortunately bought unqualified devices.

            // ... Your response ...
            if(DEBUG) kony.print("SECURITY: NONPRODUCTION DEVICE");
        }

        if( msgid == 305       // 305: Privilege Providing Application (SU, etc.)
                || msgid == 314    // 314: System Rooted/Jailbroken
                )
        {
            // ... Your response ...
            if(DEBUG) kony.print("SECURITY: ROOTED/JAILBROKEN");
        }

        if( msgid == 307       // 307: Hacking Tool Installed
                || msgid == 308    // 308: Security Subversion Tool Installed (rooting/jailbreak exploit)
                || msgid == 315    // 315: Security Hiding Tool Installed (trying to hide root/jailbreak)
                )
        {
            // ... Your response ...
            if(DEBUG) kony.print("SECURITY: SECURITY TOOL/EXPLOIT");
        }

        if( msgid == 309       // 309: Application Tampering Tool Installed
                || msgid == 310    // 310: Game Cheat Tool Installed
                || msgid == 311    // 311: In-App Purchasing Fraud Tool Installed
                )
        {
            // ... Your response ...
            if(DEBUG) kony.print("SECURITY: CHEAT/FRAUD/TAMPER TOOL");
        }

        if( msgid == 312       // 312: Test/Automation Tool Installed
                || msgid == 318    // 318: ADBD Running (Android Developer Bridge)
                )
        {
            // NOTE: these may be appropriate on developer/non-production builds

            // ... Your response ...
            if(DEBUG) kony.print("SECURITY: DEVELOPMENT/TEST ITEMS");
        }

        if( msgid == 313       // 313: Security Expectation Failure (sandbox security is broken)
                || msgid == 411    // 411: Security Operation Failure (system security call failed)
                )
        {
            // ... Your response ...
            if(DEBUG) kony.print("SECURITY: RUNTIME OPERATION VIOLATION");
        }

        if( msgid == 400       // 400: Debugger/Instrumentation Detected
                )
        {
            // ... Your response ...
            if(DEBUG) kony.print("SECURITY: DEBUGGER DETECTED");
            
	    	if(DEBUG) kony.ui.Alert({"message":"Debugger detected", "alertTitle":"Security Violation"},{});
        }

        if( msgid == 401       // 401: Application Tampering Detected
                || msgid == 406    // 406: Stealth Callback Failure (Advanced MobileAwareness feature)
                || msgid == 416    // 416: Heartbeat failure (re: heartbeat() API call)
                )
        {
            // ... Your response ...
            if(DEBUG) kony.print("SECURITY: RUNTIME APP TAMPERING/INTEGRITY VIOLATION");
            
            if(DEBUG) kony.ui.Alert({"message":"Application tampering detected", "alertTitle":"Security Violation"},{});
        }

        if( msgid == 409    // 409: Provisioning Missing (sideloaded or not from known app store)
                || msgid == 413    // 412: Application is Developer Signed
                || msgid == 414    // 414: Debug Build (app is a debug/developer build)
                )
        {
            // NOTE: these are typically seen in development/pre-production installs, but shouldn't
            // occur on production installs going through app stores

            // ... Your response ...
            if(DEBUG) kony.print("SECURITY: VIOLATION IF NOT DEVELOPMENT BUILD");
        }

        if( msgid == 500       // 500: SSL Pin Violation (network MitM attacker detected)
                )
        {
            // ... Your response ...
            if(DEBUG) kony.print("SECURITY: NETWORK ATTACKER");
            
            if(DEBUG) kony.ui.Alert({"message":"Network attacker detected", "alertTitle":"Security Violation"},{});
        }


        if( msgid == 415 )     // 415: Provisioning Provider
        {
            // This message indicates provisioning info.
            // Android: it contains the package name of the installer, e.g. com.android.vending for Google Play
            //
            // You can test the values against expectations to see if your application is coming from unauthorized
            // stores or getting distributed via ad-hoc means

            // Android:
            // data1: string of package name of installer; may be NULL if sideloaded

            // ... Your logic ...
            if( data1 == null ){
                if(DEBUG) kony.print("SECURITY: APP IS SIDELOADED OR 3RD PARTY STORE");
            } else {
                // com.android.vending = Google Play
                // com.amazon.venezia = Amazon Store
                // com.sec.android.app.samsungapps = Samsung Store
                if(DEBUG) kony.print("INSTALLER: " + data1.toString());
            }
        }

        if( msgid == 404 )     // 404: Application Signer
        {
            // This message includes the SHA1 hash of the application signer.
            //
            // You can test the values against expectations to see if your application is resigned.
            //
            // Android:
            // data1: SHA1 hash byte array (binary, 20 bytes) of certificate used to sign APK
            // data2: (optional) text string of the certificate X509 subject
			//
            // IOS:
            // data1: SHA1 hash byte array (binary, 20 bytes) of certificate used to sign executable
            // data2: (optional) text string of the certificate X509 subject
            //
            // You will need to know your signer certificate hashes (production and optionally
            // developer) ahead of time in order to include them here; or, run this once
            // with the target signer, get the signer value from logcat (below), then insert it
            // back in.

            // ... Your logic ...
            var signer_hash = "(Unknown)";
            if( data1 != null ) signer_hash = data1.toString();
            if(DEBUG) kony.print("SECURITY: Application signer hash = " + signer_hash);
            
            // If you know the intended production signer, you can include the hash
			// here and verify against it.  Since the production signer shouldn't
			// change often (never for Android, typically never for IOS), you can embed
			// them here.
			//
			//if(data1 != null ){
			//	var expected_hash_ios = "...";
			//	var expected_hash_android= "...";
			//	
			//	if( !data1.toString().equals(expected_hash_ios) && 
			//		!data1.toString().equals(expected_hash_android))
			//	{
			//		// Unexpected signer, respond appropriately ...
			//	}	
			//} 
        }

        if( msgid == 407 )     // 407: Application Measurement
        {
            // This message includes the SHA1 hash of the application bundle.
            //
            // You can test the values against expectations to see if your application has been modified.

            if (msgsubid == 10)    // 10: APK file
            {
                // Android: This is SHA1 hash of the APK file
                // data1: SHA1 hash byte array (binary, 20 bytes) of the APK
                // data2: string of the file name/path on device
                //
                // Since any changes here ultimately affect the APK, and thus the measurement of the
                // APK, you will need to dynamically retrieve the value from runtime (e.g. download
                // expected values from a REST service) if you want to provide in-app enforcement.
                // Otherwise, this same measurement value is (optionally) also reported to the backend
                // message gateway receiver, where you can remotely track any APK modifications
                // separate/external to this code.

                // ... Your logic ...
                var measure_hash = "(Unknown)";
                if( data1 != null ) measure_hash = data1.toString();
                if(DEBUG) kony.print("SECURITY: APK measurement hash = " + measure_hash);

            }

            if( msgsubid == 1 )    // 1: .so or executable file
            {
                // Android: this is the SHA1 hash of the shared library file holding the MobileAwareness logic
                // data1: SHA1 hash byte array (binary, 20 bytes) of the library
                // data2: string of the file name/path on device
                //
                // IOS: this is the SHA1 hash of the executable file holding the MobileAwareness logic
                // data1: SHA1 hash byte array (binary, 20 bytes) of the executable
                // data2: string of the file name/path on device
				//
                // ANDROID NOTE: this is the hash of the loaded library (libasma.so or your .so); given multiple
                // architectures, there is a different hash for each supported architecture (armeabi,
                // arm64-v8a, x86, etc.).  The hashes are effectively the SHA1 sum of each of the library
                // files you include.  Assuming the library files aren't rebuilt with your project, you
                // can build your native libraries, take the hashes, put them here, then build the
                // Java portions of your app and package it all up -- the library hashes won't change
                // during that process.

                // ... Your logic ...
                var measure_hash = "(Unknown)";
                if( data1 != null ) measure_hash = data1.toString();
                if(DEBUG) kony.print("SECURITY: Native executable/library measurement hash = " + measure_hash);
            }
        }
        
        if( msgid == 408 )     // 408: Provisioning Signer
        {
            // This message includes the SHA1 hash of the application provisioning profile signer.
            //
            // You can test the values against expectations to see if your application is resigned.
			//
            // IOS:
            // data1: SHA1 hash byte array (binary, 20 bytes) of certificate used to sign provisioning profile
            // data2: (optional) text string of the certificate X509 subject
            //
            // You will need to know your signer certificate hashes (production and optionally
            // developer) ahead of time in order to include them here; or, run this once
            // with the target signer, get the signer value from logcat (below), then insert it
            // back in.

            // ... Your logic ...
            var signer_hash = "(Unknown)";
            if( data1 != null ) signer_hash = data1.toString();
            if(DEBUG) kony.print("SECURITY: Provisioning signer hash = " + signer_hash);            
        }
}


/////////////////////////////////////////////////////////////////////////
// TYPICALLY DO NOT NEED TO EDIT PAST THIS POINT

//
// Logic to determine if this is a MobileAwareness compatible platform
//

//#undef MOBILEAWARENESS_COMPATIBLE

//#ifdef iphone
//#define MOBILEAWARENESS_COMPATIBLE
//#endif

//#ifdef ipad
//#define MOBILEAWARENESS_COMPATIBLE
//#endif

//#ifdef android
//#define MOBILEAWARENESS_COMPATIBLE
//#endif

//#ifdef tabrcandroid
//#define MOBILEAWARENESS_COMPATIBLE
//#endif


//#ifndef MOBILEAWARENESS_COMPATIBLE
//// Platform is NOT compatible; we will use stubs/mock functionality

function MobileAwareness_init_internal(cb)
{
	// For stub purposes, we "fake" a msgid=50 (Initialization Complete)
	// to the callback -- that way the callback can reasonably expect
	// to wait for completion on any platform.
	if( cb ){
		cb(50, 0, null, null);
	}
	
	// And now just return success
	return 0;
}

// The rest of the functions are stubs/mocks that always return success
function MobileAwareness_registerIdentity(ident){ return 0; }
function MobileAwareness_sendMessage(msgid, data){ return 0; }
function MobileAwareness_heartbeat(input){ return 0; }
function MobileAwareness_loginStatus(status){}
function MobileAwareness_networkReachability(){}
function MobileAwareness_version(){ return 0; }
function MobileAwareness_securityPosture(){ return 0x0001; }


//#else
//// Platform IS compatible; we will call through to the FFI

function MobileAwareness_init_internal(cb){
	return MobileAwarenessKony.initialize(cb);
}
function MobileAwareness_registerIdentity(ident){ 
	return MobileAwarenessKony.registerIdentity(ident);
}
function MobileAwareness_sendMessage(msgid, data){ 
	return MobileAwarenessKony.sendMessage(msgid,data);
}
function MobileAwareness_heartbeat(input){ 
	return MobileAwarenessKony.heartbeat(input);
}
function MobileAwareness_loginStatus(status){
	MobileAwarenessKony.loginStatus(status);
}
function MobileAwareness_networkReachability(){
	MobileAwarenessKony.networkReachability();
}
function MobileAwareness_version(){
	return MobileAwarenessKony.version();
}
function MobileAwareness_securityPosture(){ 
	return MobileAwarenessKony.securityPosture();
}

//#endif

//
// Polling-based functions
//

function MobileAwareness_isJailbroken(){
	if( MobileAwareness_securityPosture() & 0x0004 ) return true;
	return false;
}
function MobileAwareness_isHackingToolInstalled(){
	if( MobileAwareness_securityPosture() & 0x0020 ) return true;
	return false;
}
function MobileAwareness_isSecurityViolationEncountered(){
	if( MobileAwareness_securityPosture() & 0x0080 ) return true;
	return false;
}
function MobileAwareness_isDebuggerDetected(){
	if( MobileAwareness_securityPosture() & 0x0100 ) return true;
	return false;
}
function MobileAwareness_isApplicationTamperingDetected(){
	if( MobileAwareness_securityPosture() & 0x0200 ) return true;
	return false;
}
function MobileAwareness_isNetworkAttackDetected(){
	if( MobileAwareness_securityPosture() & 0x0400 ) return true;
	return false;
}
function MobileAwareness_isMalwareDetected(){
	if( MobileAwareness_securityPosture() & 0x0800 ) return true;
	return false;
}
function MobileAwareness_isGameCheatToolDetected(){
	if( MobileAwareness_securityPosture() & 0x1000 ) return true;
	return false;
}
function MobileAwareness_isDeveloperArtifactsDetected(){
	if( MobileAwareness_securityPosture() & 0x2000 ) return true;
	return false;
}
