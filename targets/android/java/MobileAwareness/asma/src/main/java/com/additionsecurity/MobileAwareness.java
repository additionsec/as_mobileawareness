package com.additionsecurity;

import android.content.Context;
import android.content.Intent;
import android.provider.Settings;

import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;

/*
 * Main API class, this is aligned with customer-provided documentation.
 */

public class MobileAwareness {

    // Prevent us from being garbage collected by holding a reference to this class
    private static Class<?> _self = MobileAwareness.class;

    // Static load of library
    static {
        if( BuildConfig.BUILD_TYPE.equals("standalone") ) {
            //
            // Standalone will automatically load libasma; embedded has to load
            // it explicitly via some other means
            //
            try {
                System.loadLibrary("asma");
            } catch (Exception e) {
                throw new LibraryException("");
            }
        }
    }

    public static class OperationException extends Exception { public OperationException(String s){super();}}
    public static class LibraryException extends RuntimeException { public LibraryException(String s){super();}}
    public static class ConfigurationFileException extends RuntimeException { public ConfigurationFileException(String s){super();}}
    public static class LicenseException extends OperationException { public LicenseException(String s){super(s);}}
    public static class SecurityException extends OperationException { public SecurityException(String s){super(s);}}

    private static boolean _initialized = false;

    public static void initialize( Context ctx, IMobileAwarenessCallback callback )
            throws OperationException
    {
        if( _initialized ){
            // save our callback; null is allowed
            _callback = callback;

            return;
        }

        // Get the Android ID
        String andid = Settings.Secure.getString(ctx.getContentResolver(), Settings.Secure.ANDROID_ID);

        // NOTE: leading zeros are absent from the value; it's supposed to be a 64-bit value
        while( andid.length() < 16 ){
            andid = "0" + andid;
        }

        byte[] id = new byte[0];
        if( andid != null ) {
            // Convert it to hex bytes
            id = new byte[andid.length() /2];
            for (int i = 0; i < id.length; i ++) {
                id[i] = (byte) ((Character.digit(andid.charAt(i*2), 16) << 4)
                        + Character.digit(andid.charAt((i*2) + 1), 16));
            }
        }

        initialize(ctx, callback, id);
    }

    public static void initialize( final Context ctx, IMobileAwarenessCallback callback, byte[] id )
            throws OperationException
    {
        if( _initialized ){
            // save our callback; null is allowed
            _callback = callback;

            return;
        }


        // Load our configuration out of assets and into memory
        byte[] config_buffer;
        try {
            InputStream is = ctx.getAssets().open("as.conf");
            config_buffer = new byte[ is.available() ];
            is.read(config_buffer);
            is.close();
        }
        catch(Exception e)
        {
            throw new ConfigurationFileException("");
        }

        initialize(ctx, callback, id, config_buffer);
    }

    public static synchronized void initialize( final Context ctx, IMobileAwarenessCallback callback,
                                   byte[] id, byte[] config )
            throws OperationException
    {

        // save our callback; null is allowed
        _callback = callback;

        if( _initialized ) return;

        // Do the configure
        int res = B.c(0, id, config);

        // Check the configure return code, and translate it into an exception
        if( res == -2 /*LICENSE*/ ) throw new LicenseException("");
        else if( res == -3 /*INTEGRITY*/ ) throw new SecurityException("");
        else if( res == -5 /*OLDCONFIG*/ ) throw new ConfigurationFileException("");
        else if( res != 0 && res != -6 /*ALREADYINIT*/ ) throw new OperationException("");

        // If we get here, it was AS_INIT_SUCCESS or AS_INIT_ERR_ALREADYINIT
        _initialized = true;
    }

    public static long version(){ return MobileAwareness.B.z( /*VERSION:*/6, 0, null); }
    public static void networkEvent( final Intent i ){ MobileAwareness.B.z( /*NETWORK:*/1, 0, null); }
    public static long heartbeat(long in){ return MobileAwareness.B.z( /*HEARTBEAT:*/2, in, null); }

    public static void registerIdentity(String useridentity) throws OperationException
    {
        if( MobileAwareness.B.z( /*REGISTERIDENTITY:*/4, 0, useridentity) != 0 ) throw new OperationException("");
    }

    public static void sendMessage(long id, String msg) throws OperationException
    {
        if( MobileAwareness.B.z( /*CUSTOMERMESSAGE:*/5, id, msg) != 0 ) throw new OperationException("");
    }

    public static void loginStatus(boolean success)
    {
        if( success ) MobileAwareness.B.z( /*LOGINSTATUS:*/3, 1, null);
        else MobileAwareness.B.z( /*LOGINSTATUS:*/3, 0, null);
    }

    public static class SecurityPosture {
        public boolean completed;
        public boolean emulator;
        public boolean rooted;
        public boolean nonProduction;
        public boolean hackingTool;
        public boolean securityFailure;
        public boolean debugger;
        public boolean tampering;
        public boolean network;
        public boolean malware;
        public boolean cheatOrFraudTool;
        public boolean devBuild;
        public boolean devTool;
    }

    public static SecurityPosture securityPosture(){
        long posture = MobileAwareness.B.z( /*POSTURE:*/7, 0, null);
        SecurityPosture p = new SecurityPosture();
        if( (posture & 0x0001) > 0 ) p.completed = true;
        if( (posture & 0x0002) > 0 ) p.emulator = true;
        if( (posture & 0x0004) > 0 ) p.rooted = true;
        if( (posture & 0x0010) > 0 ) p.nonProduction = true;
        if( (posture & 0x0020) > 0 ) p.hackingTool = true;
        if( (posture & 0x0080) > 0 ) p.securityFailure = true;
        if( (posture & 0x0100) > 0 ) p.debugger = true;
        if( (posture & 0x0200) > 0 ) p.tampering = true;
        if( (posture & 0x0400) > 0 ) p.network = true;
        if( (posture & 0x0800) > 0 ) p.malware = true;
        if( (posture & 0x1000) > 0 ) p.cheatOrFraudTool = true;
        if( (posture & 0x2000) > 0 ) p.devBuild = true;
        if( (posture & 0x4000) > 0 ) p.devTool = true;
        return p;
    }

    /*package*/ static IMobileAwarenessCallback _callback = null;

    /*package*/ static class B { // BRIDGE

        /*package*/ static native int c(int flags, byte[] id, byte[] config); // CONFIGURE

        /*package*/ static native long z(int w, long l, Object o); // IPC

        // NOTE: do not change this definition, it is called by native code:
        /*package*/ static void cb(int a, int b, byte[] c, byte[] d) {

            // To avoid TOCTOU between null check & onMessage, we copy the value locally
            IMobileAwarenessCallback cb = _callback;

            if( cb != null ){
                try {
                    cb.onMessage(a, b, c, d);
                }
                catch(Throwable t){
                    // swallow on purpose, it's best effort
                }
            }
        }
    }
}

