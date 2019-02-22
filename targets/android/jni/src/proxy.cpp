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

extern "C" {

#include <arpa/inet.h>

#include "as_mobileawareness.h"
#include "as_ma_private.h"
#include "as_ma_platform.h"
#include "config.h"
#include "ascti_tests.h"
#include "seed.h"
#include "tf_netsec.h"


// TODO:
#define ERRORBASE_PROXY		50000

static const uint32_t JAVAUTILLIST[] = {0x33dbb486,0x1de32f7,0x3fefe2c6,0x6c966de9,}; // "java/util/List"
static const uint32_t SIZE[] = {0x37d7bc9f,0x6ca64fc1,}; // "size"
static const uint32_t I[] = {0x52e4fcc4,}; // "()I"
static const uint32_t GET[] = {0x52d9b08b,}; // "get"
static const uint32_t ILJAVALANGOBJECT[] = {0x1e849cc4,0x24830ef0,0x1d9f9d82,0x2ca949b9,0x17afcb88,0x5cce28e9,}; // "(I)Ljava/lang/Object;"
static const uint32_t HTTP[] = {0x22d9a184,0x79877de0,}; // "http://"
static const uint32_t HTTPS[] = {0x22d9a184,0x568768a9,0x1fa97f4,}; // "https://"


#define WORK_MAX	8

#define _S1(nom) _decode((sizeof(nom)/4)-1,nom,work1)
#define _S2(nom) _decode((sizeof(nom)/4)-1,nom,work2)

#ifndef STR_DECODE
#define STR_DECODE
#define _STR_START      0x52add5ec
#endif


///////////////////////////////////////////////////////////////////
// Cached classes & methods
//
jclass jc_ps, jc_uri;
jmethodID jm_psgd, jm_pss, jm_uric, jm_lsize, jm_lget, jm_addr, jm_ghn, jm_ghp;
jobject jo_noproxy;


///////////////////////////////////////////////////////////////////
// Error helpers
//
static int _jerr(JNIEnv *env, void* var)
{
	if( env->ExceptionCheck() == JNI_TRUE ){
		env->ExceptionClear();
		return 1;
	}
	if( (void*)var == NULL ){
		return 2;
	}
	return 0;
}
#define JERET(var,n) if(_jerr(env,var) != 0) return n


///////////////////////////////////////////////////////////////////
// Proxy init code (caches classes)
//
int proxy_init( JNIEnv *env )
{
	uint32_t work1[WORK_MAX], work2[WORK_MAX]; // for obfuscated strings

	// TODO: obfuscate strings

	jclass c_list = NULL;
	jclass c_proxy = NULL;
	jclass c_isa = NULL;
	jfieldID f_noprox = NULL;

        // Control flow flattening
        uint32_t seed = SEED_START;
        while(1){
          uint32_t s = _SEED_NEXT(seed);
          switch(s){

        case SEED_1:
		jc_ps = env->FindClass("java/net/ProxySelector");
		JERET( jc_ps, __LINE__ );
		break;
	case SEED_2:
		jc_ps = (jclass)env->NewGlobalRef(jc_ps);
		JERET(jc_ps, __LINE__ );
		break;

	case SEED_3:
		jm_psgd = env->GetStaticMethodID(jc_ps, "getDefault", "()Ljava/net/ProxySelector;");
		JERET( jm_psgd, __LINE__ );
		break;
	case SEED_4:
		jm_pss = env->GetMethodID(jc_ps, "select", "(Ljava/net/URI;)Ljava/util/List;");
		JERET( jm_pss, __LINE__ );
		break;

	case SEED_5:
		jc_uri = env->FindClass("java/net/URI");
		JERET( jc_ps, __LINE__ );
		break;
	case SEED_6:
		jc_uri = (jclass)env->NewGlobalRef(jc_uri);
		JERET( jc_uri, __LINE__ );
		break;

	case SEED_7:
		jm_uric = env->GetMethodID(jc_uri, "<init>", "(Ljava/lang/String;)V");
		JERET( jm_uric, __LINE__ );
		break;

	case SEED_8:
		c_list = env->FindClass(_S1(JAVAUTILLIST));
		JERET( c_list, __LINE__ );
		break;
	case SEED_9:
		jm_lsize = env->GetMethodID( c_list, _S1(SIZE), _S2(I) );
		JERET( jm_lsize, __LINE__ );
		break;
	case SEED_10:
		jm_lget = env->GetMethodID( c_list, _S1(GET), _S2(ILJAVALANGOBJECT) );
		JERET( jm_lget, __LINE__ );
		break;
	case SEED_11:
		env->DeleteLocalRef(c_list);

	case SEED_12:
		c_proxy = env->FindClass("java/net/Proxy");
		JERET( c_proxy, __LINE__ );
		break;
	case SEED_13:
		jm_addr = env->GetMethodID(c_proxy, "address", "()Ljava/net/SocketAddress;");
		JERET( jm_addr, __LINE__ );
		break;
	case SEED_14:
		f_noprox = env->GetStaticFieldID(c_proxy, "NO_PROXY", "Ljava/net/Proxy;");
		JERET( f_noprox, __LINE__ );
		break;
	case SEED_15:
		jo_noproxy = env->GetStaticObjectField(c_proxy, f_noprox);
		JERET( jo_noproxy, __LINE__ );
		break;
	case SEED_16:
		jo_noproxy = (jobject)env->NewGlobalRef(jo_noproxy);
		JERET( jo_noproxy, __LINE__ );
		break;
	case SEED_17:
		env->DeleteLocalRef(c_proxy);

	case SEED_18:
		c_isa = env->FindClass("java/net/InetSocketAddress");
		JERET( c_isa, __LINE__ );
		break;
	case SEED_19:
		jm_ghn = env->GetMethodID(c_isa, "getHostName", "()Ljava/lang/String;");
		JERET( jm_ghn, __LINE__ );
		break;
	case SEED_20:
		jm_ghp = env->GetMethodID(c_isa, "getPort", "()I");
		JERET( jm_ghp, __LINE__ );
		break;
	case SEED_21:
		env->DeleteLocalRef(c_isa);

	case SEED_22:
		return 0;

	default:
		return __LINE__;
	 } // switch
	} // while

	return __LINE__;
}

int proxy_setup( TFN_WebRequest_t *req, int report )
{
	int r, res = 0;
	jobject o_ps = NULL;
	jobject o_uri = NULL;
	jobject o_lp = NULL;
	jobject o_sa = NULL;
	jobject o_proxy = NULL;
	jstring uri_str = NULL;
	jstring hostname = NULL;
	char * c_hostname = NULL;
	JNIEnv *env;
	int do_detach = 0;
	jint count, port;
	struct sockaddr_in proxy_addr;
	uint32_t work1[WORK_MAX]; // for obfuscated strings

	char buffer[TFN_MAX_HOSTNAME + 8 + 6 + 1]; // + "https://" + ":XXXXX/"
	buffer[0] = 0;
	char *ptr = buffer;

	//
	// It's possible we are called before init, depending upon error paths
	//
	if( jc_ps == NULL || jm_lget == NULL ) return 0;

	//
	// Might need to attach a VM
	//
	r = _PLATFORM_CONFIG.vm->GetEnv((void**)&env, JNI_VERSION_1_6);
	if( r == JNI_EDETACHED ){
		if( _PLATFORM_CONFIG.vm->AttachCurrentThread(&env, NULL) != 0){
			ALOG("CI:ERR: Unable to attach current thread");
			if( report ) error_report( ERRORBASE_PROXY+__LINE__,0,0);
			return 0;
		}
		do_detach = 1;

	} else if( r != JNI_OK ){
		ALOG("CI:ERR: GetEnv returned error");
		if( report ) error_report( ERRORBASE_PROXY+__LINE__,0,0);
		return 0;
	}

	//
	// Call ProxySelector.getDefault()
	//
	o_ps = env->CallStaticObjectMethod(jc_ps, jm_psgd);
	if( env->ExceptionCheck() == JNI_TRUE ){
		env->ExceptionClear();
		ALOG("CI:ERR: PS.getDefault() returned error");
		if( report ) error_report( ERRORBASE_PROXY+__LINE__,0,0);
		goto done;
	}
	if( o_ps == NULL ){
		// We will treat NULL as no selector, not an error
		goto done;
	}

	// Construct URL 
	MEMSET(buffer, 0, sizeof(buffer));
	if( (req->flags & TFN_WEBREQUEST_FLAG_SSL) > 0 ){
		MEMCPY( ptr, _S1(HTTPS), 8);
		ptr += 8;
	} else {
		MEMCPY( ptr, _S1(HTTP), 7);
		ptr += 7;
	}
	MEMCPY( ptr, req->hostname, STRLEN(req->hostname) );
	ptr += STRLEN(req->hostname);
	*ptr = ':'; ptr++;
	ptr += ITOA(req->port, ptr);

	ALOG("CI:TAG: URL to proxy: '%s'", buffer);

	// Convert URL to Java String
	uri_str = env->NewStringUTF(buffer);
	if( env->ExceptionCheck() == JNI_TRUE || uri_str == NULL ){
		env->ExceptionClear();
		ALOG("CI:ERR: NewString() returned error");
		if( report ) error_report( ERRORBASE_PROXY+__LINE__,0,0);
		goto done;
	}

	// Create URI object using string
	o_uri = env->NewObject(jc_uri, jm_uric, uri_str);
	if( env->ExceptionCheck() == JNI_TRUE || o_uri == NULL ){
		env->ExceptionClear();
		ALOG("CI:ERR: URI() returned error");
		if( report ) error_report( ERRORBASE_PROXY+__LINE__,0,0);
		goto done;
	}

	// Call ProxySelector.select(Uri)
	o_lp = env->CallObjectMethod(o_ps, jm_pss, o_uri);
	if( env->ExceptionCheck() == JNI_TRUE ){
		env->ExceptionClear();
		ALOG("CI:ERR: ps.select() returned error");
		if( report ) error_report( ERRORBASE_PROXY+__LINE__,0,0);
		goto done;
	}
	if( o_lp == NULL ) goto done;

	// now use List.Size and List.Get to unpack res
	count = env->CallIntMethod( o_lp, jm_lsize );
	if( env->ExceptionCheck() == JNI_TRUE ){
		env->ExceptionClear();
		ALOG("CI:ERR: list.size() returned error");
		if( report ) error_report( ERRORBASE_PROXY+__LINE__,0,0);
		goto done;
	}
	if( count > 0 ){
		// We only process the first entry
		o_proxy = env->CallObjectMethod( o_lp, jm_lget, 0 );
		if( _jerr(env, o_proxy) != 0 ){
			ALOG("CI:ERR: list.Get() returned error");
			if( report ) error_report( ERRORBASE_PROXY+__LINE__,0,0);
			goto done;
		}

		// Compare to see if this is Proxy.NO_PROXY object
		if( env->IsSameObject(o_proxy, jo_noproxy) ){
			// NO_PROXY object
			ALOG("CI:TAG: selector returned NO_PROXY");
			goto done;
		}

		// [Inet]SocketAddress = Proxy.address()
		o_sa = env->CallObjectMethod( o_proxy, jm_addr );
		if( _jerr(env, o_sa) == 1 ){
			ALOG("CI:ERR: proxy.address() returned error");
			if( report ) error_report( ERRORBASE_PROXY+__LINE__,0,0);
			goto done;
		}
		if( o_sa == NULL ){ // Allowed, means go direct
			ALOG("CI:TAG: proxy address is NULL");
			goto done;
		}

		// String hostname = InetSocketAddress.getHostName()
		hostname = (jstring)env->CallObjectMethod( o_sa, jm_ghn );
		if( _jerr(env, hostname) != 0 ){
			ALOG("CI:ERR: isa.getHostName() returned error");
			if( report ) error_report( ERRORBASE_PROXY+__LINE__,0,0);
			goto done;
		}

		// int port = InetSocketAddress.getPort()
		port = env->CallIntMethod( o_sa, jm_ghp );
		if( _jerr(env, hostname) != 0 ){ // NOTE: use hostname for NULL check
			ALOG("CI:ERR: isa.getPort() returned error");
			if( report ) error_report( ERRORBASE_PROXY+__LINE__,0,0);
			goto done;
		}

		c_hostname = (char*)env->GetStringUTFChars( hostname, NULL );
		if( _jerr(env, c_hostname) != 0 ){
			ALOG("CI:ERR: isa.getPort() returned error");
			if( report ) error_report( ERRORBASE_PROXY+__LINE__,0,0);
			goto done;
		}

		ALOG("CI:TAG: Proxy found host=%s port=%d", c_hostname, port);
		ASCTI_Item_t item;
		ctiitem_setup_app( &item );
		item.test = CTI_TEST_PROXYCONFIGURED;
		item.data1_type = ASCTI_DT_HOSTNAME;
		item.data1_len = STRLEN(c_hostname);
		item.data1 = c_hostname;
		item.data3_type = ASCTI_DT_PORT;
		item.data3 = port;
		message_add( &item );

		// Do DNS lookup
		if( TFN_DNS_Lookup( c_hostname, port, &proxy_addr ) == 0 && proxy_addr.sin_port > 0 ){
			// Set up the proxy into the req
			req->flags |= TFN_WEBREQUEST_FLAG_PROXY;
			MEMCPY( &req->destination, &proxy_addr, sizeof(proxy_addr) );
			res = 1;
		} else {
			// TODO: report error? report a "proxy configured but lookup failed?"
			// Fall through to just going direct
		}
		
		env->ReleaseStringUTFChars( hostname, c_hostname );
		env->DeleteLocalRef(o_proxy);
		o_proxy = NULL;
	} else {
		ALOG("CI:TAG: no proxies returned by selector");
	}

done:
	if( o_proxy != NULL ) env->DeleteLocalRef(o_proxy);
	if( hostname != NULL ) env->DeleteLocalRef(hostname);
	if( uri_str != NULL ) env->DeleteLocalRef(uri_str);
	if( o_sa != NULL ) env->DeleteLocalRef(o_sa);
	if( o_uri != NULL ) env->DeleteLocalRef(o_uri);
	if( o_lp != NULL ) env->DeleteLocalRef(o_lp);
	if( o_ps != NULL ) env->DeleteLocalRef(o_ps);
	if( do_detach ) _PLATFORM_CONFIG.vm->DetachCurrentThread();

	ALOG("CI:TAG: Proxy check result=%d", res);
	return res;
}

} // extern
