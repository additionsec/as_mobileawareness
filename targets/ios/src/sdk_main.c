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

#include <CoreFoundation/CoreFoundation.h>
#include <objc/runtime.h>
#include <objc/message.h>

#include <stdlib.h>
#include <uuid/uuid.h>

#include "tf_persist.h"
#include "tf_cal.h"

#include "as_mobileawareness.h"
#include "as_ma_private.h"
#include "as_ma_platform.h"
#include "as_cti.h"
#include "config.h"
#include "observations/checkhook.h"

#include "seed.h"

#define ERRORBASE 55000

#define WORK_MAX	6
static const uint32_t LIBRARYAS[] = {0x30c499c3,0x12c70bef,0x6ac9959d,0x39b06ec1,}; // "/Library/as/"
static const uint32_t CFBUNDLEVERSION[] = {0x27ef93af,0x19f2049f,0x3dfd9e94,0x6eea0aa1,}; // "CFBundleVersion"
static const uint32_t UIDEVICE[] = {0x37e99cb9,0x9fb0691,0x5e86f9cc,}; // "UIDevice"
static const uint32_t CURRENTDEVICE[] = {0x20dfa08f,0x3fda3db4,0xbceb48c,0x58b74fb5,}; // "currentDevice"
static const uint32_t IDENTIFIERFORVENDOR[] = {0x3cc8b185,0xedf2baf,0x36e4a697,0xbf80bb9,0x44ef8386,}; // "identifierForVendor"

#define _S(nom) _decode((sizeof(nom)/4)-1,nom,work)


//
// The global platform config structure
// 
struct _platform_config _PLATFORM_CONFIG;


//
// Helper function to do all the URL to string error checking
//
static int _url_to_path( CFURLRef url_, char path[ASMA_PATH_MAX], uint32_t len )
{
	if( url_ == NULL ) return error_report(ERRORBASE+__LINE__, 0, -1);
	CFStringRef path_ = CFURLCopyFileSystemPath(url_, kCFURLPOSIXPathStyle);
	CFRelease(url_);
	if( path_ == NULL ) return error_report(ERRORBASE+__LINE__, 0, -1);
	int res = CFStringGetCString(path_, path, len, kCFStringEncodingUTF8);
	CFRelease(path_);
	if( !res ) return error_report(ERRORBASE+__LINE__, 0, -1);
	return 0;
}


//
// Bridge the callback into IOS form
//
static void (*_callback_ref)(int,int,CFDataRef,CFDataRef) = NULL;
static void _callback_bridge_objc(int a, int b, ASCTI_Item_t *item)
{
	CFDataRef d1 = NULL;
	CFDataRef d2 = NULL;

	if( _callback_ref == NULL ) return;

	if( item != NULL ){
		if( item->data1 != NULL && item->data1_len > 0 )
			d1 = CFDataCreate(NULL, item->data1, item->data1_len);
		if( item->data2 != NULL && item->data2_len > 0 )
			d2 = CFDataCreate(NULL, item->data2, item->data2_len);
	}

	_callback_ref(a,b,d1,d2);

	if( d1 != NULL ) CFRelease(d1);
	if( d2 != NULL ) CFRelease(d2);
}


//
// Bridge the callback into native form (Unity)
//
static void (*_callback_n_ref)(int,int,uint8_t*,uint32_t,uint8_t*,uint32_t) = NULL;
static void _callback_bridge_n(int a, int b, ASCTI_Item_t *item)
{
	if( _callback_n_ref == NULL ) return;

	if( item != NULL )
		_callback_n_ref( a, b, item->data1, item->data1_len, item->data2, item->data2_len );
	else
		_callback_n_ref( a, b, NULL, 0, NULL, 0 );
}


#if __cplusplus
extern "C" {
#endif

// Forward declaration:
static int _initialize( const uuid_t deviceid, void(*cb)(int,int,ASCTI_Item_t*) );


//
// Unity entry point
//
__attribute__ ((visibility ("default")))
int AS_Initialize_Direct( 
	const uuid_t deviceid, 
	const uint8_t *config, uint32_t config_len, 
	const uint8_t *defs, uint32_t defs_len,
	void(*callback)(int,int,uint8_t*,uint32_t,uint8_t*,uint32_t) 
	)
{
	// Save our native callback reference (may be NULL)
	_callback_n_ref = (void(*)(int,int,uint8_t*,uint32_t,uint8_t*,uint32_t))callback;

	// If we are bootstrapped, we are done (we do allow updating the callback tho)
	if( _CONFIG.flag_bootstrapped > 0 ) return AS_INIT_ERR_ALREADYINIT;

	// Save our pointers
	_PLATFORM_CONFIG.defs = defs;
	_PLATFORM_CONFIG.defs_len = (uint32_t) defs_len;
	_PLATFORM_CONFIG.config = config;
	_PLATFORM_CONFIG.config_len = (uint32_t) config_len;

	return _initialize( deviceid, _callback_bridge_n );
}

//
// Main library entry point
//
__attribute__ ((visibility ("default")))
int AS_Initialize( const uuid_t deviceid, void(*callback)(int,int,CFDataRef,CFDataRef) )
{
	// Save our objc callback reference (maybe NULL)
	_callback_ref = (void(*)(int,int,CFDataRef,CFDataRef))callback;

	// If we are bootstrapped, we are done (we do allow updating the callback tho)
	if( _CONFIG.flag_bootstrapped > 0 ) return AS_INIT_ERR_ALREADYINIT;

	return _initialize( deviceid, _callback_bridge_objc );
}

static int _initialize( const uuid_t deviceid, void(*cb)(int,int,ASCTI_Item_t*) )
{
	ALOG("CI:TAG: AS: Initializing\n");
	uint32_t work[WORK_MAX];

	int found = 0, record;
	CHECK_HOOK(asl_add_log_file, found, record);
	CHECK_HOOK(CFBundleGetMainBundle, found, record);
	CHECK_HOOK(CFBundleGetIdentifier, found, record);
	CHECK_HOOK(CFBundleGetValueForInfoDictionaryKey, found, record);
	CHECK_HOOK(CFBundleCopyBundleURL, found, record);
	CHECK_HOOK(CFCopyHomeDirectoryURL, found, record);
	CHECK_HOOK(bootstrap_ex, found, record);
	CHECK_HOOK(bootstrap, found, record);
	CHECK_HOOK(MMAP_NOM, found, record);
	REPORT_HOOKING(found, record);
	if( found > 0 ) return AS_INIT_ERR_INTEGRITY;

	asl_add_log_file(NULL, STDERR_FILENO);

	//
	// Get the application name
	//
	CFBundleRef mainBundle = CFBundleGetMainBundle();
	CFStringRef bundleId = (mainBundle == NULL ) ? NULL : CFBundleGetIdentifier(mainBundle);
	if( bundleId == NULL ) return error_report(ERRORBASE+__LINE__, 0, -1);

	char appnom[sizeof(_CONFIG.pkg)];
	MEMSET( appnom, 0, sizeof(appnom) );
	if( CFStringGetLength(bundleId) > (sizeof(appnom)-1) ) return error_report(ERRORBASE+__LINE__, 0, -1);
	if( !CFStringGetCString(bundleId, appnom, sizeof(appnom)-1, kCFStringEncodingUTF8))
		return error_report(ERRORBASE+__LINE__, 0, -1);
	ALOG("CI:TAG: Appnom: %s", appnom);


	//
	// Get the application version
	//
	// NOTE: we tolerate failures here
	char appver[sizeof(_CONFIG.pkgver)];
	MEMSET(appver, 0, sizeof(appver));
	appver[0] = '-';
	// NOTE: NOT-MVP-TODO: obfuscate the CFSTR
	CFStringRef ver_ = CFBundleGetValueForInfoDictionaryKey( mainBundle, CFSTR("CFBundleVersion") );
	if( ver_ == NULL ) error_report(ERRORBASE+__LINE__,0,0);
	else {
		CFIndex l_ = CFStringGetLength(ver_);
		if( !CFStringGetCString(ver_, appver, sizeof(appver), kCFStringEncodingUTF8) )
			error_report(ERRORBASE+__LINE__,0,0);
	}
	ALOG("CI:TAG: Appver: %s", appver);


	//
	// Get the base path directory (rpath), which is the app bundle path (read-only)
	//
	char rpath[ASMA_PATH_MAX];
	if( _url_to_path( CFBundleCopyBundleURL(mainBundle), rpath, sizeof(rpath)-2 ) != 0 ) 
		return error_report(ERRORBASE+__LINE__,0, -1);
	int l = STRLEN(rpath);
	rpath[l] = '/'; // append trailing slash
	rpath[l+1] = 0;
	ALOG("CI:TAG: rpath: %s", rpath);


	//
	// Get the cache path, which is used as Library/as/ for our file writes
	//
	// NON-MVP-TODO: we can get this from HOME env?
	char cpath[ASMA_PATH_MAX];
	_S(LIBRARYAS);
	if( _url_to_path( CFCopyHomeDirectoryURL(), cpath, 
		sizeof(cpath)-STRLEN((char*)work)-1) != 0 )
		return error_report(ERRORBASE+__LINE__,0, -1);
	l = STRLEN(cpath);
	MEMCPY( &cpath[l], (char*)work, STRLEN((char*)work)+1 ); // +1 for NULL
	ALOG("CI:TAG: cpath: %s", cpath);
	

	//
	// Get the ID
	//
	ASSERT( sizeof(uuid_t) >= 16 );
	uint8_t uuid[32];
	MEMSET( uuid, 0, sizeof(uuid) );
	MEMCPY( uuid, deviceid, sizeof(uuid_t) );


	//
	// We got our info, now bootstrap!
	//
	int res;
	if( _PLATFORM_CONFIG.config != NULL ){

		// Config is const, so we have to make a copy so we can decode it in mem
		uint8_t *config_mem  = (uint8_t*)MMAP( NULL, _PLATFORM_CONFIG.config_len, 
			PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANON, -1, 0 );

		if( config_mem == MAP_FAILED ) {
			res = _BOOTSTRAP_SETUP;
			error_report(ERRORBASE+__LINE__,errno,0);
		} else {
			res = bootstrap_ex(appnom, appver, rpath, cpath, uuid, cb, 0, 
				config_mem, _PLATFORM_CONFIG.config_len);
			MUNMAP(config_mem, _PLATFORM_CONFIG.config_len);
		}
	}
	else {
		res = bootstrap(appnom, appver, rpath, cpath, uuid, cb, 0);
	}

	// Translate the bootstrap result into SDK return value
	switch(res){
		case _BOOTSTRAP_OK: return AS_INIT_SUCCESS;
		case _BOOTSTRAP_LICENSE: return AS_INIT_ERR_LICENSE;
		case _BOOTSTRAP_INTEGRITY: return AS_INIT_ERR_INTEGRITY;
	}
	return AS_INIT_ERR_GENERAL;
}



//
// Identity registration function
//
__attribute__ ((visibility ("default")))
int AS_Register_Identity( const char *identity )
{
	if( identity == NULL || _CONFIG.flag_bootstrapped == 0 ) return AS_ERR_GENERAL;
	return customer_identity( identity );
}



//
// Customer message
//
__attribute__ ((visibility ("default")))
int AS_Send_Message( uint32_t id, const char *data )
{
	if( data == NULL || _CONFIG.flag_bootstrapped == 0 ) return AS_ERR_GENERAL;
	return customer_message( id, data );
}


//
// Login Status
//
__attribute__ ((visibility ("default")))
void AS_Login_Status( int status )
{
	if( _CONFIG.flag_bootstrapped == 0 ) return;
	customer_login_status( status );
}


//
// Network Reachability
//
__attribute__ ((visibility ("default")))
void AS_Network_Reachability()
{
	if( _CONFIG.flag_bootstrapped == 0 ) return;
	customer_reachability();
}


//
// Heartbeat
//
__attribute__ ((visibility ("default")))
long AS_Heartbeat(long i)
{
	return heartbeat(i);
}


//
// Library version reporting
//
__attribute__ ((visibility ("default")))
uint32_t AS_Version()
{
	return ASVERSION;
}


//
// Security posture reporting, which runs heartbeat
//
__attribute__ ((visibility ("default")))
uint32_t AS_Security_Posture()
{
	// Same as a heartbeat, without the nonce checking stuff:
	heartbeat_internal();
	return analytics_get_posture();
}


//
// Retrieve the last known persistent identity, or create one
//
__attribute__ ((visibility ("default")))
int AS_Device_Identity(uuid_t uuid)
{
	ASSERT(sizeof(uuid_t) == 16);
	uint32_t work[WORK_MAX];
	void *obj = NULL;

	uint32_t seed = SEED_START;
	while(1){
	  uint32_t s = _SEED_NEXT(seed);
	  switch(s)
	  {
		case SEED_1:
		{
			uint32_t len = sizeof(uuid_t);
			if( TFP_Get_Ex( (uint8_t*)_P_DEVICEID, NULL, uuid, &len, NULL, 0, NULL ) == TFP_OK ){
				if( len == 16 ){
					ALOG("CI:TAG: Restored previous identity");
					return 0;
				}
			}
		}
		break;

		case SEED_2:
		{
			// Get IDFV
			ALOG("CI:TAG: Generating identity");
			obj = objc_getClass(_S(UIDEVICE));
		}
		break;

		case SEED_3:
		{
			if( obj != NULL ){
				obj = objc_msgSend(obj, sel_getUid(_S(CURRENTDEVICE)));
			}
		}
		break;

		case SEED_4:
		{
			if( obj != NULL ){
				obj = objc_msgSend(obj, sel_getUid(_S(IDENTIFIERFORVENDOR)));
			}
		}
		break;

		case SEED_5:
		{
			if( obj != NULL ){
				CFUUIDBytes cfbytes = CFUUIDGetUUIDBytes((CFUUIDRef)obj);
				ASSERT( sizeof(CFUUIDBytes) >= sizeof(uuid_t) );
				MEMCPY( uuid, &cfbytes, sizeof(uuid_t) );
			}
		}
		break;

		case SEED_6:
		{
			if( obj == NULL ){
				// If we get here, we didn't get IDFV; so fall back to something random and save it
				// Error report, to track how often IDFV doesn't work in the field
				error_report(ERRORBASE+__LINE__, 1, 0);
				TCL_Random( uuid, sizeof(uuid_t) );
			}
		}
		break;

		case SEED_7:
		{
			if( TFP_Set_Ex( (uint8_t*)_P_DEVICEID, NULL, uuid, sizeof(uuid_t), NULL, 0, NULL ) != TFP_OK ){
				// We can survive - just report the error and move on
				error_report(ERRORBASE+__LINE__, 0, 0);
			}
		}
		break;

		case SEED_8:
			return 0;

		default:
			return error_report(ERRORBASE+__LINE__, 0, -1);

	  } // switch
	} // while

}


#if __cplusplus
}
#endif
