package com.konylabs.ffi;
import java.util.HashMap;
import java.util.Hashtable;
import java.util.Vector;
import com.konylabs.api.TableLib;
import com.konylabs.vm.LuaTable;



import com.additionsecurity.MobileAwareness;
import com.konylabs.libintf.Library;
import com.konylabs.libintf.JSLibrary;
import com.konylabs.vm.LuaError;
import com.konylabs.vm.LuaNil;


public class N_MobileAwarenessKony extends JSLibrary {

 
 
	public static final String initialize = "initialize";
 
 
	public static final String registerIdentity = "registerIdentity";
 
 
	public static final String sendMessage = "sendMessage";
 
 
	public static final String heartbeat = "heartbeat";
 
 
	public static final String loginStatus = "loginStatus";
 
 
	public static final String networkReachability = "networkReachability";
 
 
	public static final String version = "version";
 
 
	public static final String securityPosture = "securityPosture";
 
	String[] methods = { initialize, registerIdentity, sendMessage, heartbeat, loginStatus, networkReachability, version, securityPosture };


 Library libs[] = null;
 public Library[] getClasses() {
 libs = new Library[0];
 return libs;
 }



	public N_MobileAwarenessKony(){
	}

	public Object[] execute(int index, Object[] params) {
		// TODO Auto-generated method stub
		Object[] ret = null;
 try {
		int paramLen = params.length;
 int inc = 1;
		switch (index) {
 		case 0:
 if (paramLen != 1){ return new Object[] {new Double(100),"Invalid Params"}; }
 com.konylabs.vm.Function callback0 = null;
 if(params[0] != null && params[0] != LuaNil.nil) {
 callback0 = (com.konylabs.vm.Function)params[0];
 }
 ret = this.initialize( callback0 );
 
 			break;
 		case 1:
 if (paramLen != 1){ return new Object[] {new Double(100),"Invalid Params"}; }
 java.lang.String ident1 = null;
 if(params[0] != null && params[0] != LuaNil.nil) {
 ident1 = (java.lang.String)params[0];
 }
 ret = this.registerIdentity( ident1 );
 
 			break;
 		case 2:
 if (paramLen != 2){ return new Object[] {new Double(100),"Invalid Params"}; }
 Double msgid2 = null;
 if(params[0] != null && params[0] != LuaNil.nil) {
 msgid2 = (Double)params[0];
 }
 java.lang.String data2 = null;
 if(params[1] != null && params[1] != LuaNil.nil) {
 data2 = (java.lang.String)params[1];
 }
 ret = this.sendMessage( msgid2, data2 );
 
 			break;
 		case 3:
 if (paramLen != 1){ return new Object[] {new Double(100),"Invalid Params"}; }
 Double input3 = null;
 if(params[0] != null && params[0] != LuaNil.nil) {
 input3 = (Double)params[0];
 }
 ret = this.heartbeat( input3 );
 
 			break;
 		case 4:
 if (paramLen != 1){ return new Object[] {new Double(100),"Invalid Params"}; }
 Boolean status4 = null;
 if(params[0] != null && params[0] != LuaNil.nil) {
 status4 = (Boolean)params[0];
 }
 ret = this.loginStatus( status4 );
 
 			break;
 		case 5:
 if (paramLen != 0){ return new Object[] {new Double(100),"Invalid Params"}; }
 ret = this.networkReachability( );
 
 			break;
 		case 6:
 if (paramLen != 0){ return new Object[] {new Double(100),"Invalid Params"}; }
 ret = this.version( );
 
 			break;
 		case 7:
 if (paramLen != 0){ return new Object[] {new Double(100),"Invalid Params"}; }
 ret = this.securityPosture( );
 
 			break;
 		default:
			break;
		}
 }catch (Exception e){
			ret = new Object[]{e.getMessage(), new Double(101), e.getMessage()};
		}
		return ret;
	}

	public String[] getMethods() {
		// TODO Auto-generated method stub
		return methods;
	}
	public String getNameSpace() {
		// TODO Auto-generated method stub
		return "MobileAwarenessKony";
	}


	/*
	 * return should be status(0 and !0),address
	 */
 
 
 	public final Object[] initialize( com.konylabs.vm.Function inputKey0 ){
 
		Object[] ret = null;
 Double val = new Double(com.additionsecurity.MobileAwareness.initializeKony( (com.konylabs.vm.Function)inputKey0
 ));
 
 			ret = new Object[]{val, new Double(0)};
 		return ret;
	}
 
 
 	public final Object[] registerIdentity( java.lang.String inputKey0 ){
 
		Object[] ret = null;
 Double val = new Double(com.additionsecurity.MobileAwareness.registerIdentity( inputKey0
 ));
 
 			ret = new Object[]{val, new Double(0)};
 		return ret;
	}
 
 
 	public final Object[] sendMessage( Double inputKey0, java.lang.String inputKey1 ){
 
		Object[] ret = null;
 Double val = new Double(com.additionsecurity.MobileAwareness.sendMessage( inputKey0.longValue() , inputKey1
 ));
 
 			ret = new Object[]{val, new Double(0)};
 		return ret;
	}
 
 
 	public final Object[] heartbeat( Double inputKey0 ){
 
		Object[] ret = null;
 Double val = new Double(com.additionsecurity.MobileAwareness.heartbeat( inputKey0.longValue() ));
 
 			ret = new Object[]{val, new Double(0)};
 		return ret;
	}
 
 
 	public final Object[] loginStatus( Boolean inputKey0 ){
 
		Object[] ret = null;
 com.additionsecurity.MobileAwareness.loginStatus( inputKey0.booleanValue() );
 
 ret = new Object[]{LuaNil.nil, new Double(0)};
 		return ret;
	}
 
 
 	public final Object[] networkReachability( ){
 
		Object[] ret = null;
 com.additionsecurity.MobileAwareness.networkEvent( );
 
 ret = new Object[]{LuaNil.nil, new Double(0)};
 		return ret;
	}
 
 
 	public final Object[] version( ){
 
		Object[] ret = null;
 Double val = new Double(com.additionsecurity.MobileAwareness.version( ));
 
 			ret = new Object[]{val, new Double(0)};
 		return ret;
	}
 
 
 	public final Object[] securityPosture( ){
 
		Object[] ret = null;
 Double val = new Double(com.additionsecurity.MobileAwareness.securityPosture( ));
 
 			ret = new Object[]{val, new Double(0)};
 		return ret;
	}
 
};
