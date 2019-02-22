package ...;

import android.util.Log;
import com.additionsecurity.IMobileAwarenessCallback;

public class CallbackExample implements IMobileAwarenessCallback {

    @Override
    public void onMessage(int id, int subid, byte[] data1, byte[] data2)
    {

        //
        // Indication that the initial security scan is complete
        //
        if( id == 50 )      // 50: Initialization Complete
        {
            // The basic security information has been reported; at this point
            // you can make go/no-go security decisions based on what was
            // previously reported.

            // ... Your logic ...
        }


        //
        // Malware on the device
        //
        if( id == 150       // 150: Known Malware Artifact Detected
                || id == 152    // 152: Known Malware Signer Present
                )
        {
            // ... Your response ...
            Log.i("App", "SECURITY: MALWARE");
        }

        //
        // Application vulnerabilities
        //
        if( id == 252       // 252: Open Application Local Attack Vector
                || id == 253    // 253: Open Application Remote Attack Vector
                )
        {
            // These are likely items you would want to address before you ship
            // to production, as they represent open vulnerabilities.  For example,
            // debug is enabled in your manifest.

            // ... Your response ...
            Log.i("App", "SECURITY: APP VULNERABILITY");
        }

        if( id == 300        // 300: Synthetic System (Emulator/Simulator)
                )
        {
            // ... Your response ...
            Log.i("App", "SECURITY: EMULATOR");
        }

        if( id == 302       // 302: Non-Production System
                || id == 317    // 317: System Unsigned (Android)
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
            Log.i("App", "SECURITY: NONPRODUCTION DEVICE");
        }

        if( id == 305       // 305: Privilege Providing Application (SU, etc.)
                || id == 314    // 314: System Rooted/Jailbroken
                )
        {
            // ... Your response ...
            Log.i("App", "SECURITY: ROOTED/JAILBROKEN");
        }

        if( id == 307       // 307: Hacking Tool Installed
                || id == 308    // 308: Security Subversion Tool Installed (rooting/jailbreak exploit)
                || id == 315    // 315: Security Hiding Tool Installed (trying to hide root/jailbreak)
                )
        {
            // ... Your response ...
            Log.i("App", "SECURITY: SECURITY TOOL/EXPLOIT");
        }

        if( id == 309       // 309: Application Tampering Tool Installed
                || id == 310    // 310: Game Cheat Tool Installed
                || id == 311    // 311: In-App Purchasing Fraud Tool Installed
                )
        {
            // ... Your response ...
            Log.i("App", "SECURITY: CHEAT/FRAUD/TAMPER TOOL");
        }

        if( id == 312       // 312: Test/Automation Tool Installed
                || id == 318    // 318: ADBD Running (Android Developer Bridge)
                )
        {
            // NOTE: these may be appropriate on developer/non-production builds

            // ... Your response ...
            Log.i("App", "SECURITY: DEVELOPMENT/TEST ITEMS");
        }

        if( id == 313       // 313: Security Expectation Failure (sandbox security is broken)
                || id == 411    // 411: Security Operation Failure (system security call failed)
                )
        {
            // ... Your response ...
            Log.i("App", "SECURITY: RUNTIME OPERATION VIOLATION");
        }

        if( id == 400       // 400: Debugger/Instrumentation Detected
                )
        {
            // ... Your response ...
            Log.i("App", "SECURITY: DEBUGGER DETECTED");
        }

        if( id == 401       // 401: Application Tampering Detected
                || id == 406    // 406: Stealth Callback Failure (Advanced MobileAwareness feature)
                || id == 416    // 416: Heartbeat failure (re: heartbeat() API call)
                )
        {
            // ... Your response ...
            Log.i("App", "SECURITY: RUNTIME APP TAMPERING/INTEGRITY VIOLATION");
        }

        if( id == 409    // 409: Provisioning Missing (sideloaded or not from known app store)
                || id == 413    // 412: Application is Developer Signed
                || id == 414    // 414: Debug Build (app is a debug/developer build)
                )
        {
            // NOTE: these are typically seen in development/pre-production installs, but shouldn't
            // occur on production installs going through app stores

            // ... Your response ...
            Log.i("App", "SECURITY: VIOLATION IF NOT DEVELOPMENT BUILD");
        }

        if( id == 500       // 500: SSL Pin Violation (network MitM attacker detected)
                )
        {
            // ... Your response ...
            Log.i("App", "SECURITY: NETWORK ATTACKER");
        }


        if( id == 415 )     // 415: Provisioning Provider
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
                Log.i("App", "SECURITY: APP IS SIDELOADED OR 3RD PARTY STORE");
            } else {
                final String installer = new String(data1);
                // com.android.vending = Google Play
                // com.amazon.venezia = Amazon Store
                // com.sec.android.app.samsungapps = Samsung Store
                Log.i("APP", "INSTALLER: " + installer);
            }


        }

        if( id == 404 )     // 404: Application Signer
        {
            // This message includes the SHA1 hash of the application signer.
            //
            // You can test the values against expectations to see if your application is resigned.
            //
            // Android:
            // data1: SHA1 hash byte array (binary, 20 bytes) of certificate used to sign APK
            // data2: (optional) text string of the certificate X509 subject
            //
            // You will need to know your signer certificate hashes (production and optionally
            // developer) ahead of time in order to include them here; or, run this once
            // with the target signer, get the signer value from logcat (below), then insert it
            // back in.

            // ... Your logic ...
            String signer_hash = "(Unknown)";
            if( data1 != null ) signer_hash = bytesToHex(data1);
            Log.i("APP", "SECURITY: Application signer hash = " + signer_hash);

        }

        if( id == 407 )     // 407: Application Measurement
        {
            // This message includes the SHA1 hash of the application bundle.
            //
            // You can test the values against expectations to see if your application has been modified.

            if (subid == 10)    // 10: APK file
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
                String measure_hash = "(Unknown)";
                if( data1 != null ) measure_hash = bytesToHex(data1);
                Log.i("APP", "SECURITY: APK measurement hash = " + measure_hash);

            }

            if( subid == 1 )    // 1: .so file
            {
                // Android: this is the SHA1 hash of the shared library file holding the MobileAwareness logic
                // data1: SHA1 hash byte array (binary, 20 bytes) of the library
                // data2: string of the file name/path on device
                //
                // NOTE: this is the hash of the loaded library (libasma.so or your .so); given multiple
                // architectures, there is a different hash for each supported architecture (armeabi,
                // arm64-v8a, x86, etc.).  The hashes are effectively the SHA1 sum of each of the library
                // files you include.  Assuming the library files aren't rebuilt with your project, you
                // can build your native libraries, take the hashes, put them here, then build the
                // Java portions of your app and package it all up -- the library hashes won't change
                // during that process.

                // ... Your logic ...
                String measure_hash = "(Unknown)";
                if( data1 != null ) measure_hash = bytesToHex(data1);
                Log.i("APP", "SECURITY: Native library measurement hash = " + measure_hash);
            }
        }

    }


    final protected static char[] hexArray = "0123456789ABCDEF".toCharArray();
    private static String bytesToHex(byte[] bytes) {
        char[] hexChars = new char[bytes.length * 2];
        for ( int j = 0; j < bytes.length; j++ ) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = hexArray[v >>> 4];
            hexChars[j * 2 + 1] = hexArray[v & 0x0F];
        }
        return new String(hexChars);
    }

}
