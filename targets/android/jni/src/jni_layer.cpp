// Copyright 2019 J Forristal LLC
// Copyright 2016 Addition Security Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include <jni.h>
#include <stdlib.h>
#include <stdint.h>

#include "as_mobileawareness.h"
#include "as_ma_private.h"
#include "as_ma_platform.h"
#include "config.h"
#include "ascti_tests.h"
#include "seed.h"

#define ERRORBASE 23000 

/////////////////////////////////////////////////////////////////////
// Cached method and class objects (populated by AS_JNI_Onload)
//

static jmethodID method_cb = NULL;
static jclass clazz_bridge = NULL;


/////////////////////////////////////////////////////////////////////
// Obfuscated strings
//

#define WORK_MAX	16
static const uint32_t COMADDITIONSECURITYMOBILEAWARENESSB[] = {0x7dc0ba8f,0x4fd52db0,0x76c7bb99,0x50dd25b6,0x66ccab9f,0x4fc205ea,0x49ca86da,0x6fd10cf5,0x63f7becc,0x18a62fbe,}; // "com/additionsecurity/MobileAwareness$B"

static const uint32_t IIBBV[] = {0x9e49cc4,0x7bd734d8,0x2caacbd3,}; // "(II[B[B)V"
static const uint32_t IBBI[] = {0x10f69cc4,0x2ae2dc1,0x55d3d29c,}; // "(I[B[B)I"

static const uint32_t IJLJAVALANGOBJECTJ[] = {0x1ee79cc4,0x24e00ef0,0x1dfc9d82,0x2cca49b9,0x17cccb88,0x5ce701e9,}; // "(IJLjava/lang/Object;)J"

#define _S1(nom) _decode((sizeof(nom)/4)-1,nom,work1)
#define _S2(nom) _decode((sizeof(nom)/4)-1,nom,work2)


/////////////////////////////////////////////////////////////////////
// Error handling functions & macros
//

#define JERR(var) (_exception_check(env) || (void*)var == NULL )

static int _jerr(JNIEnv *env, void* var, int n)
{
	if( var == NULL || env->ExceptionCheck() == JNI_TRUE ){
		env->ExceptionClear();
		ALOG("CI:ERR JNI %d", n);
		return error_report(ERRORBASE+__LINE__,n,-1);
	}
	return 0;
}

#define JERET(var, n, err) if(_jerr(env,(void*)var,n)!=0) return err;


/////////////////////////////////////////////////////////////////////
// JNI Function implementations
//

static inline void java_netnotify( JNIEnv *env, jobject *ignore )
{
	if( _CONFIG.flag_bootstrapped == 0 ) return;
	customer_reachability();
}

static inline jint java_register_identity( JNIEnv *env, jobject *ignore, jstring jidentity )
{
	if( jidentity == NULL || _CONFIG.flag_bootstrapped == 0 ) return AS_ERR_GENERAL;
	const char *ident = env->GetStringUTFChars( jidentity, NULL );
	if( ident == NULL ) return AS_ERR_GENERAL;
	int ret = customer_identity( ident );
	env->ReleaseStringUTFChars( jidentity, ident );
	return ret;
}

static inline jint java_send_message( JNIEnv *env, jobject *ignore, jlong jid, jstring jdata )
{
	// SPECIAL HANDLING: values >= 0xffff0000 are internal indicators
	if( jid >= 0xffff0000 ){
		ALOG("CI:TAG: Send message internal 0x%lx", (unsigned long)jid);
		return AS_SUCCESS;
	}

	if( jdata == NULL || _CONFIG.flag_bootstrapped == 0 ) return AS_ERR_GENERAL;
	const char *dat = env->GetStringUTFChars( jdata, NULL );
	if( dat == NULL ) return AS_ERR_GENERAL;
	int ret = customer_message( (uint32_t)jid, dat );
	env->ReleaseStringUTFChars( jdata, dat );
	return ret;
}

static inline void java_login_status( JNIEnv *env, jobject *ignore, jint status )
{
	if( _CONFIG.flag_bootstrapped == 0 ) return;
	customer_login_status( status );
}


static inline jlong java_heartbeat( JNIEnv *env, jobject *ignore, jlong inp)
{
	if( _CONFIG.flag_bootstrapped == 0 ) return 0;
	return (jlong)heartbeat((uint32_t)inp);
}

static inline jlong java_posture( JNIEnv *env, jobject *ignore, jlong inp)
{
	if( _CONFIG.flag_bootstrapped == 0 ) return 0;
	heartbeat_internal();
	return (jlong)analytics_get_posture();
}

static void jni_callback_bridge( int a1, int a2, ASCTI_Item_t *item );
static jint java_initialize( JNIEnv *env, jobject *ignore, jint flags, jbyteArray jid, jbyteArray jconfig )
{
	// Check our variables
	if( jid == NULL || jconfig == NULL ){ JERET(NULL,1, AS_INIT_ERR_GENERAL); }

	// Catch double-initializations
	if( _CONFIG.flag_bootstrapped == 1 ){ JERET(NULL,5, AS_INIT_ERR_ALREADYINIT); }

	// Convert uuid to native bytes
	uint8_t uuid[32];
	MEMSET( uuid, 0, sizeof(uuid) );
	int jid_len = env->GetArrayLength(jid);
	if( jid_len > sizeof(uuid) ) jid_len = sizeof(uuid);
	env->GetByteArrayRegion(jid, 0, jid_len, (jbyte*)uuid);
	if( env->ExceptionCheck() ){ JERET(NULL,10, AS_INIT_ERR_GENERAL); }

	// Load pointer to config bytes
	jsize config_sz = env->GetArrayLength( jconfig ); // Does not throw
	jbyte *config_ptr = env->GetByteArrayElements( jconfig, NULL );
	JERET( config_ptr, 20, AS_INIT_ERR_GENERAL );

	// Do the init
	int ret = bootstrap_pre(env, uuid, (uint8_t*)config_ptr, config_sz, jni_callback_bridge );
	env->ReleaseByteArrayElements( jconfig, config_ptr, JNI_ABORT );

	// Check for some left over exception
	if( env->ExceptionCheck() ){
		// We don't know what exception it is; clear it and just
		// throw one of ours in its place
		//env->ExceptionDescribe();
		env->ExceptionClear();

		// 1.3: we don't throw exceptions anymore, just return error code
		//env->ThrowNew(clazz_opex,""); // OperationException
		return AS_INIT_ERR_GENERAL;
	}
	else if( ret == _BOOTSTRAP_LICENSE ) return AS_INIT_ERR_LICENSE;
	else if( ret == _BOOTSTRAP_INTEGRITY ) return AS_INIT_ERR_INTEGRITY;
	else if( ret != _BOOTSTRAP_OK ) return AS_INIT_ERR_GENERAL;
	return AS_INIT_SUCCESS;
}


//
// Main Java IPC router
//
static jlong java_ipc( JNIEnv *env, jobject *ignore, jint ji, jlong jl, jobject jo )
{
	switch(ji)
	{
	case 1: // Network notify
		java_netnotify( env, ignore );
		break;

	case 2: // Heartbeat
		return java_heartbeat( env, ignore, jl );

	case 3: // Login status
		java_login_status( env, ignore, (jint)(jl & 0xff) );
		break;

	case 4: // Register identity
		return (jlong)java_register_identity( env, ignore, (jstring)jo );

	case 5: // Customer message
		return (jlong)java_send_message( env, ignore, jl, (jstring)jo );

	case 6: // Version
		return (jlong)ASVERSION;

	case 7: // Security posture
		return java_posture( env, ignore, jl );

	default:
	{
		// Unknown IPC call
		ALOG("CI:ERR: invalid IPC call");

		// It is more likely that someone making blind IPC calls is trying
		// to reverse engineer/tamper.  So we flag it as tampering.
		ASCTI_Item_t item;
		ctiitem_setup_app( &item );
		item.test = CTI_TEST_APPLICATIONTAMPERINGDETECTED;
		item.subtest = _SUBTEST_INTERNAL_INTEGRITY;
		item.data3_type = ASCTI_DT_VRID;
		item.data3 = ERRORBASE+__LINE__;
		message_add( &item );

		// Note that we *don't* report an error, since CI/QA/DEV/TEST will
		// note bad IPC calls via the ALOG CI:ERR, and we don't want to
		// receive errors if someone is trying to enumerate the IPCs.  That's
		// a runtime attack against the IPC interface, not a coding error.

		break;
	}

	} // switch

	return 0;
}



/////////////////////////////////////////////////////////////////////
// Helper functions
//

static int _resolve_cache_class( JNIEnv *env, const char *cnom, jclass* clazz ){
	jclass cl = env->FindClass(cnom);
	if( cl == NULL ) return -1;
	*clazz = reinterpret_cast<jclass>(env->NewGlobalRef(cl));
	if( *clazz == NULL ) return -1;
	return 0;
}


/////////////////////////////////////////////////////////////////////
// EXPORTED
extern "C" {

/////////////////////////////////////////////////////////////////////
// Main JNI entry point
//

int AS_JNI_OnLoad(JavaVM *vm, void *reserved)
{
	uint32_t work1[WORK_MAX], work2[WORK_MAX];
	JNIEnv *env;
	ALOG("CI:TAG: JNILoading");

	// Bridge method definitions to register
	// NOTE: single character method names OK to leave unobfuscated
	JNINativeMethod methods[] = {
		{"c",(char*)work1,	(void*)java_initialize},
		{"z",(char*)work2,	(void*)java_ipc}
	};

	// Control flow flattening
	uint32_t seed = SEED_START;
	while(1){
	  uint32_t s = _SEED_NEXT(seed);
	  switch(s){

	case SEED_1:
		if( vm->GetEnv( reinterpret_cast<void**>(&env), JNI_VERSION_1_6) != JNI_OK ) return JNI_ERR;
		break;

	case SEED_2:
		// Lookup the Bridge class
		if( _resolve_cache_class(env, _S1(COMADDITIONSECURITYMOBILEAWARENESSB), &clazz_bridge) != 0 ){
			ALOG("CI:ERR: Unable to find %s", (char*)work1); return JNI_ERR; }
		break;

	case SEED_3:
		// SPECIAL: note where work1 and work2 are in the methods array, and load the obfuscated
		// strings to match those positions:
		_S1(IBBI); // configure
		_S2(IJLJAVALANGOBJECTJ); // ipc
		if( env->RegisterNatives(clazz_bridge, methods, (sizeof(methods)/sizeof(methods[0]))) < 0 ){
			ALOG("CI:ERR: Unable to register natives"); return JNI_ERR; }
		break;

	case SEED_4:
		// NOTE: this string is ok to leave unobfuscated:
		method_cb = env->GetStaticMethodID( clazz_bridge, "cb", _S1(IIBBV) );
		break;

	case SEED_5:
		if( method_cb == NULL ){ ALOG("CI:ERR: Unable to find callback"); return JNI_ERR; }
		break;

	case SEED_6:
		ALOG("CI:TAG: JNILoad OK");
		return JNI_VERSION_1_6;
		break;

	default:
		// It'd be nice to do an integrity alert here, but we are pre-init; and,
		// we can't guarantee we even resolved the SecurityOperationException class,
		// so ultimately we just fail hard and let it be what it will be.
		return error_report( ERRORBASE+__LINE__,0,JNI_ERR);

	  } // switch
	} // while
}



/////////////////////////////////////////////////////////////////////
// Java callback proxy/thunk
//

static void jni_callback_bridge( int a1, int a2, ASCTI_Item_t *item )
{
	// Centralize vars before switch
	JNIEnv *env = NULL;
	int do_detach = 0;
	int r;
	jbyteArray barray1 = NULL;
	jbyteArray barray2 = NULL;

	// Control flow flattening
	uint32_t seed = SEED_START;
	while(1){
	  uint32_t s = _SEED_NEXT(seed);
	  switch(s){

	case SEED_1:
		// Must be configured & want callbacks
		if( _CONFIG.flag_configured == 0 ) return;
		break;

	case SEED_2:
		// We might need to attach an environment
		r = _PLATFORM_CONFIG.vm->GetEnv((void**)&env, JNI_VERSION_1_6);
		break;

	case SEED_3:
		if( r == JNI_EDETACHED ){
			if( _PLATFORM_CONFIG.vm->AttachCurrentThread(&env, NULL) != 0){
				ALOG("CI:ERR: Unable to attach current thread");
				error_report( ERRORBASE+__LINE__,0,0);
				return;
			}
			do_detach=1;
		} else if( r != JNI_OK ){
			ALOG("CI:ERR: GetEnv returned error");
			error_report( ERRORBASE+__LINE__,0,0);
			return;
		}
		break;

	case SEED_4:
		// Set up our byte arrays
		if( item->data1 != NULL ){
			barray1 = env->NewByteArray( item->data1_len );
			if( barray1 == NULL || env->ExceptionCheck() ){
				env->ExceptionClear();
				error_report( ERRORBASE+__LINE__,0,0);
				if( barray1 != NULL ) env->DeleteLocalRef(barray1);
				barray1 = NULL;
			} else {
				env->SetByteArrayRegion(barray1, 0, item->data1_len, (const jbyte*)item->data1);
				if( env->ExceptionCheck() ){
					env->ExceptionClear();
					error_report( ERRORBASE+__LINE__,0,0);
					env->DeleteLocalRef(barray1);
					barray1 = NULL;
				}
			}
		}
		break;

	case SEED_5:
		if( item->data2 != NULL ){
			barray2 = env->NewByteArray( item->data2_len );
			if( barray2 == NULL || env->ExceptionCheck() ){
				env->ExceptionClear();
				error_report( ERRORBASE+__LINE__,0,0);
				if( barray2 != NULL ) env->DeleteLocalRef(barray2);
				barray2 = NULL;
			} else {
				env->SetByteArrayRegion(barray2, 0, item->data2_len, (const jbyte*)item->data2);
				if( env->ExceptionCheck() ){
					env->ExceptionClear();
					error_report( ERRORBASE+__LINE__,0,0);
					env->DeleteLocalRef(barray2);
					barray2 = NULL;
				}
			}
		}
		break;

	case SEED_6:
		// Do the callback
		env->CallStaticVoidMethod( clazz_bridge, method_cb, a1, a2, barray1, barray2 );
		break;

	case SEED_7:
		if( env->ExceptionCheck() ){
			ALOG("CI:ERR: Exception on callback");
			error_report( ERRORBASE+__LINE__,0,0);
			//env->ExceptionDescribe();
			env->ExceptionClear();
		}
		break;

	case SEED_8:
		if( barray1 != NULL ) env->DeleteLocalRef(barray1);
		break;

	case SEED_9:
		if( barray2 != NULL ) env->DeleteLocalRef(barray2);
		break;

	case SEED_10:
		// detach as necessary
		if( do_detach ) _PLATFORM_CONFIG.vm->DetachCurrentThread();
		break;

	case SEED_11:
		return;

	default:
		ALOG("CI:ERR: ran off switch");
		ASCTI_Item_t item;
		ctiitem_setup_app( &item );
		item.test = CTI_TEST_APPLICATIONTAMPERINGDETECTED;
		item.subtest = _SUBTEST_INTERNAL_INTEGRITY;
		item.data3_type = ASCTI_DT_VRID;
		item.data3 = ERRORBASE+__LINE__;
		message_add( &item );
		return;

	  } // switch
	} // while
}

/////////////////////////////////////////////////////////////////////
// END EXPORTS
} // extern C

