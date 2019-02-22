package com.additionsecurity;

import android.content.Context;
import android.content.Intent;
import android.provider.Settings;
import android.util.Base64;

import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.util.List;
import java.util.Arrays;
import java.util.ArrayList;
import java.lang.Byte;
import java.nio.charset.Charset;

/************** KONY ADDITION ***********************/
import com.konylabs.vm.Function;
import com.konylabs.android.KonyMain;
import com.konylabs.vmintf.KonyJavaScriptVM;
/************** END KONY ADDITION ***********************/


/*
 * Main API class, this is aligned with customer-provided documentation.
 */

public class MobileAwareness {

    // Prevent us from being garbage collected by holding a reference to this class
    private static Class<?> _self = MobileAwareness.class;

    // Static load of library & install of DDMS detections
    static {
        if( BuildConfig.BUILD_TYPE.equals("standalone") ) {
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

    /************** KONY ADDITION ***********************/

    final private static char[] hexArray = "0123456789ABCDEF".toCharArray();
    private static String toHex(byte[] bytes) {
	char[] hexChars = new char[bytes.length * 2];
	for ( int j = 0; j < bytes.length; j++ ) {
		int v = bytes[j] & 0xFF;
		hexChars[j * 2] = hexArray[v >>> 4];
		hexChars[j * 2 + 1] = hexArray[v & 0x0F];
	}
	return new String(hexChars);
    }

    final private static Charset UTF8_CHARSET = Charset.forName("UTF-8");

    private static class KonyCallback implements IMobileAwarenessCallback
    {
        private final Function _cb;

        public KonyCallback(Function cb) { _cb = cb; }

        @Override
        public void onMessage(int m1, int messageSubType, byte[] data1, byte[] data2)
        {
	    String d1 = null;
	    String d2 = null;

	    try {
		if( m1 == 8 ){
			// d1 & d2 tohex
			if( data1 != null ) d1 = toHex(data1);
			if( data2 != null ) d2 = toHex(data2);
		}
		else if( m1 == 151 || m1 == 152 || m1 == 500 || m1 == 502 ){
			if( data2 != null ) d2 = toHex(data2);
			if( data1 != null ) d1 = new String(data1, UTF8_CHARSET);
		}
		else if( m1 == 316 || m1 == 404 || m1 == 407 || m1 == 408 || m1 == 413 ){
			if( data1 != null ) d1 = toHex(data1);
			if( data2 != null ) d2 = new String(data2, UTF8_CHARSET);
		}
		else {
			if( data1 != null ) d1 = new String(data1, UTF8_CHARSET);
			if( data2 != null ) d2 = new String(data2, UTF8_CHARSET);
		}
	    }
	    catch(Throwable e){
		// e.printStackTrace();
		// Swallow on purpose
	    }

            try {
                _cb.execute(new Object[]{m1, messageSubType, d1, d2} );
            }
            catch(Throwable e){
                // e.printStackTrace();
		// Swallow on purpose
            }
        }
    }

    public static int initializeKony(Function callback)
    {
        try {
            if( callback != null )
                initialize(KonyMain.getAppContext(), new KonyCallback(callback));
            else
                initialize(KonyMain.getAppContext(), null);
        }
        catch( LicenseException e ){ return -2; } // AS_INIT_ERR_LICENSE
        catch( SecurityException e ){ return -3; } // AS_INIT_ERR_INTEGRITY
        catch( Exception e ){ return -1; } // AS_INIT_ERR_GENERAL
        return 0; // AS_INIT_SUCCESS
    }
    /************** END KONY ADDITION ***********************/


    public static void initialize( Context ctx, IMobileAwarenessCallback callback ) throws OperationException
    {
        if( _initialized ){
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
            throw new  ConfigurationFileException("");
        }

        initialize(ctx, callback, id, config_buffer);
    }

    public static void initialize( final Context ctx, IMobileAwarenessCallback callback,
                                   byte[] id, byte[] config )
            throws OperationException
    {
        synchronized (MobileAwareness.class) {

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

            _initialized = true;
        }
    }

    public static long version(){ return MobileAwareness.B.z( /*VERSION:*/6, 0, null); }
    public static long heartbeat(long in){ return MobileAwareness.B.z( /*HEARTBEAT:*/2, in, null); }

    /************** KONY ADDITION ***********************/

    public static void networkEvent(){ MobileAwareness.B.z( /*NETWORK:*/1, 0, null); }

    public static int registerIdentity(String useridentity)
    {
        return (int)MobileAwareness.B.z( /*REGISTERIDENTITY:*/4, 0, useridentity);
    }
    public static int sendMessage(long id, String msg)
    {
        return (int)MobileAwareness.B.z( /*CUSTOMERMESSAGE:*/5, id, msg);
    }
    /************** END KONY ADDITION ***********************/


    public static void loginStatus(boolean success)
    {
        if( success ) MobileAwareness.B.z( /*LOGINSTATUS:*/3, 1, null);
        else MobileAwareness.B.z( /*LOGINSTATUS:*/3, 0, null);
    }

    /************** KONY ADDITION ***********************/
    /*
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
    }
    */

    public static long securityPosture(){
	return MobileAwareness.B.z( /*POSTURE:*/7, 0, null);
    }
    
    /************** END KONY ADDITION ***********************/

    /*package*/ static IMobileAwarenessCallback _callback = null;

    /*package*/ static class B { // BRIDGE

        /*package*/ static native int c(int flags, byte[] id, byte[] config); // CONFIGURE

      /*package*/ static native long z(int w, long l, Object o); // IPC


        // NOTE: do not change this definition, it is called by native code:
        /*package*/ static void cb(int a, int b, byte[] c, byte[] d) {

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

