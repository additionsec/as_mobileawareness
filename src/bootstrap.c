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

#include <stdio.h>
#include <pthread.h>
#include <errno.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdint.h>

#include "tf_netsec.h"
#include "tf_cal.h"
#include "tf_crypto.h"
#include "tf_persist.h"

#include "as_ma_private.h"
#include "as_cti.h"
#include "ascti_tests.h"
#include "seed.h"

#define ERRORBASE	30000

#include "observations_init.inline.c"
//#include "observations_debugger.inline.c"

//
// Our main global objects
//
ASMA_Config_t _CONFIG;


//
// Our global keys definition
//
#include "keys.inline.c"


//
// Other inline items
//
#include "config_parser.inline.c"
#include "observations_startup.inline.c"


//
// Helper/security function to confirm our verification keys
// haven't been tampered with; we use uint16_t so the hash
// compare values wind up embedded in the ARM instructions
// where possible, and not in separate data sections
//
__attribute__((always_inline))
inline static int _keys_verify(){
	uint8_t digest[TCL_MD5_DIGEST_SIZE];
	TCL_MD5( (uint8_t*)_KEYS, sizeof(_KEYS), digest );
	uint16_t *u16 = (uint16_t*)digest;
	if( u16[0] != KEYS_HASH1 || u16[1] != KEYS_HASH2 || u16[2] != KEYS_HASH3 ||
		u16[3] != KEYS_HASH4 || u16[4] != KEYS_HASH5 || u16[5] != KEYS_HASH6 ||
		u16[6] != KEYS_HASH7 || u16[7] != KEYS_HASH8 ){
		ALOG("CI:ERR: key hash");
#ifndef NDEBUG
		int i;
		for( i=0; i<8; i++){
			ALOG("CI:TAG: KEYHASH[%d] = 0x%x", i, u16[i]);
		}
#endif
		ASCTI_Item_t item;
		MEMSET(&item, 0, sizeof(item));
		item.test = CTI_TEST_APPLICATIONTAMPERINGDETECTED;
		item.subtest = _SUBTEST_INTERNAL_INTEGRITY;
		item.data3_type = ASCTI_DT_VRID;
		item.data3 = ERRORBASE+__LINE__;
		message_add( &item );

		return -1;
	}
	return 0;
}


//
// Version reporting
//
__attribute__((always_inline))
static inline void _version_report()
{
	uint32_t v_def = TFDefs_Version( &_CONFIG.defs_as );
	uint32_t v_conf = _CONFIG.ts_config;

	ASCTI_Item_t item;
	ctiitem_setup_app( &item );
	item.test = CTI_TEST_SDKVERSIONINFO;

	item.data1 = (void*)&v_def; // NOTE: expected little endian bytes
	item.data1_len = sizeof(uint32_t);
	item.data1_type = ASCTI_DT_ASDEFVER;

	item.data2 = (void*)&v_conf; // NOTE: expecte little endian bytes
	item.data2_len = sizeof(uint32_t);
	item.data2_type = ASCTI_DT_ASCONFTS;

	item.data3 = ASVERSION; // NOTE: this is a uint32 type, so endian is accounted for
	item.data3_type = ASCTI_DT_ASLIBVER;

	if( _CONFIG.laststart.ts_config == v_conf && _CONFIG.laststart.v_lib == ASVERSION &&
		_CONFIG.laststart.v_defs1 == v_def )
	{
		item.flag_no_send = 1;
	} else {
		// NOTE: all of these are local/internal only, so endianness is consistent
		_CONFIG.laststart.ts_config = v_conf;
		_CONFIG.laststart.v_lib = ASVERSION;
		_CONFIG.laststart.v_defs1 = v_def;
	}

	message_add( &item );
}


//
// The startup thread
//
static pthread_t _startup_thread;
static void *_startup_thread_handler( void *arg )
{
	ALOG("CI:TAG: StartupThread: start");
	uint32_t local_flags = (uint32_t)arg;

	// Common application info logging
	ASCTI_Item_t item;

#if 0
//
// BUGFIX 5/20/2016: both Android IOS report this elsewhere, so removing as redundant
//
//#if SYSTEMID == 2
	// DUE TO ANDROID LATE-RECOVERY OF THE VERSIONCODE,
	// THIS IS DISABLED FOR ANDROID (who sends it at
	// a later time, after it recovers the VC).  It's
	// pulled out of PackageInfo during packages
	// enumeration (observations_java/observations_pkgs)
//#else
        //
        // Log application version info
        //
	MEMSET(&item, 0, sizeof(item));
	item.test = CTI_TEST_APPLICATIONINFO;
        item.data1_type = ASCTI_DT_VERSTR;
        item.data1_len = STRLEN(_CONFIG.pkgver);
        item.data1 = _CONFIG.pkgver;
        message_add( &item );
//#endif
#endif

	// Control flow flattening
	uint32_t seed = SEED_START;
	while(1){
	  uint32_t s = _SEED_NEXT(seed);
	  switch(s)
	  {

	case SEED_1:
	{
		// Report our basic version information
		_version_report();
	}
	break;

	case SEED_2:
	{
		// Call platform-specific startup
		observations_startup( local_flags );
	}
	break;

	case SEED_3:
	{
		// Confirm the MD5 of the keys again
		_keys_verify();
	}
	break;

	case SEED_4:
	{
		// Invoke the (optional) stealth callbacks
		stealth_callbacks();
	}
	break;

	case SEED_5:
	{
		// Save the laststart data, which is best effort
		// NOTE: in most cases, it won't be changed; that's OK, we basically
		// "waste" one persist call per startup
		//
		ALOG("CI:TAG: Persisting laststart data");
		_CONFIG.laststart.version = _LASTSTART_VERSION;
		if( TFP_Set_Ex( (uint8_t*)_P_LASTSTART, _CONFIG.cpath, (uint8_t*)&_CONFIG.laststart, 
				sizeof(_CONFIG.laststart), _CONFIG.id_sys1, ASMA_SYSID_MAX, _CONFIG.pkg) != TFP_OK ){
			error_report(ERRORBASE+__LINE__,0,0); }
	}
	break;

	case SEED_6:
	{
		// Push the messages out while we wait for scbs
		messages_flush();
	}
	break;

	case SEED_7:
	{
		// Wait for stealth callbacks to conclude
		stealth_callbacks_conclude();
	}
	break;

	case SEED_8:
	{
		// Mark us completed
		_CONFIG.flag_startup_completed = 1;
	}
	break;

	case SEED_9:
	{
		// send initializationdone message to callback, to tell the app it can proceed
		// NOTE: automation looks for this, even if there is no callback; the message_add
		// will throw it away if there is no callback, so we are just going to do it regardless
		//if( _CONFIG.flag_cb ){
       	 		MEMSET( &item, 0, sizeof(item) );
			item.test = CTI_TEST_INITIALIZATIONCOMPLETE;
			item.flag_no_send = 1;
			message_add( &item );
		//}
	}
	break;

	case SEED_10:
	{
		ALOG("CI:TAG: StartupThread: end");
		return NULL;
	}

	default:
	{
		ALOG("CI:ERR: fell off switch");
		ASCTI_Item_t item;
		MEMSET( &item, 0, sizeof(item));
		item.test = CTI_TEST_APPLICATIONTAMPERINGDETECTED;
		item.subtest = _SUBTEST_INTERNAL_INTEGRITY;
		item.data3 = ERRORBASE+__LINE__;
		item.data3_type = ASCTI_DT_VRID;
		message_add( &item );
		return NULL;
	}

	} // switch
	} // while

	return NULL; // Shouldn't actually ever get here
}



//
// Main bootstrap functions; bootstrap_ex takes an in-memory config, while bootstrap
// will load a config file into memory then call bootstrap_ex
//

// Not used?:
//#define SYSIDSZ 32

int bootstrap_ex( const char appnom[ASMA_PKG_MAX], const char appver[ASMA_PKGVER_MAX],
	const char *rpath, const char *cpath, const uint8_t sysid[ASMA_SYSID_MAX], 
	void(*callback)(int,int,ASCTI_Item_t*), uint32_t flags_local,
	uint8_t *config, uint32_t config_len )
{
	ALOG("CI:TAG: Bootstrap: start");
	ALOG("CI:TAG: VERSION=%d", ASVERSION);
	int res;
	
#ifndef NDEBUG
	ALOG("CI:TAG: uuid=%02x%02x%02x%02x"
		"%02x%02x%02x%02x"
		"%02x%02x%02x%02x"
		"%02x%02x%02x%02x",
		sysid[0], sysid[1], sysid[2], sysid[3],
		sysid[4], sysid[5], sysid[6], sysid[7],
		sysid[8], sysid[9], sysid[10], sysid[11],
		sysid[12], sysid[13], sysid[14], sysid[15]
	);
#endif

	// Control flow flattening
	uint32_t seed = SEED_START;
	while(1){
	  uint32_t s = _SEED_NEXT(seed);
	  switch(s)
	  {

	case SEED_1:
	{
		// Process the configuration values
		TFMEMCPY( _CONFIG.id_sys1, &sysid[0], ASMA_SYSID_MAX );
	}
	break;

	case SEED_2:
	{
		TFMEMCPY( _CONFIG.pkg, &appnom[0], ASMA_PKG_MAX );
		_CONFIG.pkg_sz = STRLEN(_CONFIG.pkg);
	}
	break;

	case SEED_3:
	{
		TFMEMCPY( _CONFIG.pkgver, &appver[0], ASMA_PKGVER_MAX );
	}
	break;

	case SEED_4:
	{
		// NOTE: these all +1 for NULL:
		if( (STRLEN(rpath)+1) >= ASMA_PATH_MAX ) return _BOOTSTRAP_SETUP; 
		TFMEMCPY( _CONFIG.rpath, rpath, STRLEN(rpath)+1 );
	}
	break;

	case SEED_5:
	{
		// NOTE: these all +1 for NULL:
		if( (STRLEN(cpath)+1) >= ASMA_PATH_MAX ) return _BOOTSTRAP_SETUP; 
		TFMEMCPY( _CONFIG.cpath, cpath, STRLEN(cpath)+1 );
	}
	break;

	case SEED_6:
	{
		// Set up some default (which may be overridden by config)
		_CONFIG.flag_analytics_coalesce = 1;
	}
	break;

	case SEED_7:
	{
		// Make sure the cache dir exists (it may not on IOS)
		res = ACCESS((char*)_CONFIG.cpath, F_OK);
	}
	break;

	case SEED_8:
	{
		if( res != 0 ){ // ACCESS() result; cache dir doesn't exist
			if( MKDIR((char*)_CONFIG.cpath, 0700) != 0 && errno != EEXIST ){
				ALOG("CI:ERR: unable to create cpath '%s'", _CONFIG.cpath);
				return error_report(ERRORBASE+__LINE__,0,_BOOTSTRAP_SETUP);
			}
		}
	}
	break;

	case SEED_9:
	{
		// Saving our callback
		// NOTE: allowed to be NULL:
		_CONFIG.msg_callback = callback;
		if( _CONFIG.msg_callback != NULL ) _CONFIG.flag_cb = 1;
	}
	break;

	case SEED_10:
	{	
		// Init the guarded_data
		if( guarded_init() != 0 ){
			// NOTE: already error_report
			return _BOOTSTRAP_SETUP;
		}

		// For testing:
		//error_report(31337,31338,0); 
	}
	break;

	case SEED_11:
	{
		// Confirm the MD5 (checksum) of the keys
		if( _keys_verify() != 0 ){
			return error_report(ERRORBASE+__LINE__,0,_BOOTSTRAP_INTEGRITY);
		}
	}
	break;

	case SEED_12:
	{
		ALOG("CI:TAG: BOOTSTRAP: config_parse...");
		// NOTE: config ptr is modified in memory, so it can't be const
		res = config_parse( config, config_len );
	}
	break;

	case SEED_13:
	{
		if( res != _CONFIG_OK ){
			ALOG("CI:ERR: unable to parse config");
			if( res == _CONFIG_ERR_SIG ){
				if( callback != NULL ) callback( CTI_TEST_APPLICATIONTAMPERINGDETECTED, 
					_SUBTEST_INTERNAL_CONFIGSIG, NULL );
				return _BOOTSTRAP_INTEGRITY;
			}
			else if( res == _CONFIG_ERR_INTEGRITY ){
				if( callback != NULL ) callback( CTI_TEST_APPLICATIONTAMPERINGDETECTED, 
					_SUBTEST_INTERNAL_CONFIGINTEGRITY, NULL );
				return _BOOTSTRAP_INTEGRITY;
			}
			else if( res == _CONFIG_ERR_LICENSE ) return _BOOTSTRAP_LICENSE;
			else if( res == _CONFIG_ERR_OLDFORMAT ) return _BOOTSTRAP_OLDCONFIG;
			return _BOOTSTRAP_SETUP;
		}
		_CONFIG.flag_configured = 1;
	}
	break;

	case SEED_14:
	{
		// Start getting CTI configured & subsystems online, so we can message items
		// sooner rather than later

		// Initialize our CTI config	
		ASSERT( sizeof(_CONFIG.cti_config.system) <= sizeof(_CONFIG.id_sys1) );
		TFMEMCPY( _CONFIG.cti_config.system, sysid, sizeof(_CONFIG.cti_config.system) );
		_CONFIG.cti_config.has_system = 1;
	}
	break;

	case SEED_15:
	{
		ASSERT( sizeof(_CONFIG.cti_config.org) <= sizeof(_CONFIG.id_org) );
		TFMEMCPY( _CONFIG.cti_config.org, _CONFIG.id_org, sizeof(_CONFIG.cti_config.org) );
		_CONFIG.cti_config.has_org = 1;
       	 	_CONFIG.cti_config.app = _CONFIG.pkg;

		_CONFIG.cti_config.version = ASVERSION;
	}
	break;

	case SEED_16:
	{
		ASSERT( sizeof(_CONFIG.cti_config.otp) == 32 );
		TCL_SHA256( _CONFIG.id_sys1, ASMA_SYSID_MAX, (uint8_t*)&_CONFIG.cti_config.otp );
	}
	break;

	case SEED_17:
	{
		// Initialize subsystems

		ALOG("CI:TAG: BOOTSTRAP: web_init...");
		if( TFN_Web_Init() != 0 ){
			ALOG("CI:ERR: unable to init web");
			return error_report(ERRORBASE+__LINE__,0,_BOOTSTRAP_SETUP);
		}
	}
	break;

	case SEED_18:
	{
		ALOG("CI:TAG: BOOTSTRAP: messages_init...");
		if( messages_init() != 0 ){
			ALOG("CI:ERR: unable to init messages");
			return error_report(ERRORBASE+__LINE__,0,_BOOTSTRAP_SETUP);
		}
	}
	break;

	case SEED_19:
	{
		// Report out which keys we used for signing
		ASCTI_Item_t item;

		if( _CONFIG.key_root != NULL && _CONFIG.key_root_len > 0 ){
			MEMSET( &item, 0, sizeof(item) );
			item.test = CTI_TEST_SIGNINGKEY;
			item.data1_type = ASCTI_DT_RAWBINARY;
			item.data1 = _CONFIG.key_root;
			item.data1_len = _CONFIG.key_root_len;
			message_add( &item );
		}
		if( _CONFIG.key_config != NULL && _CONFIG.key_config_len > 0 ){
			MEMSET( &item, 0, sizeof(item) );
			item.test = CTI_TEST_SIGNINGKEY;
			item.subtest = 1;
			item.data1_type = ASCTI_DT_RAWBINARY;
			item.data1 = _CONFIG.key_config;
			item.data1_len = _CONFIG.key_config_len;
			message_add( &item );
		}

	}
	break;

	case SEED_20:
	{
		// Now that we have org_id via config, check last known ID
		uint32_t idlen = ASMA_SYSID_MAX;
		uint8_t prior[ASMA_SYSID_MAX];
		uint32_t res = TFP_Get_Ex( (uint8_t*)_P_ID1, _CONFIG.cpath, prior, &idlen,
			_CONFIG.id_org, ASMA_ORGID_MAX, _CONFIG.pkg );
		if( res == TFP_INTEGRITY ){
			ALOG("CI:ERR: TFP get ID1 integrity error");
			ASCTI_Item_t item;
			MEMSET( &item, 0, sizeof(item) );
			item.test = CTI_TEST_APPLICATIONTAMPERINGDETECTED;
			item.subtest = _SUBTEST_INTERNAL_PERSISTINTEGRITY;
			item.data3 = ERRORBASE+__LINE__;
			item.data3_type = ASCTI_DT_VRID;
			message_add( &item );

			// Overwrite it with blank data, so we don't keep hitting this issue
			TFP_Set_Ex( (uint8_t*)_P_ID1, _CONFIG.cpath, NULL,  0, _CONFIG.id_org, ASMA_ORGID_MAX, _CONFIG.pkg );
		}
		else if( res == TFP_OK ){
			if( MEMCMP(prior, _CONFIG.id_sys1, ASMA_SYSID_MAX) != 0 ){
				// The system ID changed from what is prior saved

				// Inform of the ID change
				ASCTI_Item_t item;
				MEMSET(&item, 0, sizeof(item));
				item.test = CTI_TEST_SYSTEMIDCHANGED;
				item.data1 = prior;
				item.data1_len = sizeof(prior);
				item.data1_type = ASCTI_DT_SYSID;
				message_add( &item );

				// Delete any prior persists, since they are protected by the sysid
				if( TFP_Set_Ex( (uint8_t*)_P_ID2, _CONFIG.cpath, NULL, 0, NULL, 0, _CONFIG.pkg ) != TFP_OK )
				{
					error_report(ERRORBASE+__LINE__,0,0);
				}
				if( TFP_Set_Ex( (uint8_t*)_P_LASTSTART, _CONFIG.cpath, NULL, 0, NULL, 0, _CONFIG.pkg ) != TFP_OK )
				{
					error_report(ERRORBASE+__LINE__,0,0);
				}
			}
		}
	}
	break;

	case SEED_21:
	{
		// Save the current ID
		if( TFP_Set_Ex( (uint8_t*)_P_ID1, _CONFIG.cpath, _CONFIG.id_sys1, ASMA_SYSID_MAX,
			_CONFIG.id_org, ASMA_ORGID_MAX, _CONFIG.pkg ) != TFP_OK )
		{
			error_report(ERRORBASE+__LINE__,0,0);
		}
	}
	break;

	case SEED_22:
	{
		// Load a second identity, if it exists
		ASSERT( _CONFIG.flag_configured == 1 );

		if( _CONFIG.flag_disable_user2_persist == 0 ){
			uint32_t idlen = ASMA_USER2_MAX;
			uint32_t res = TFP_Get_Ex( (uint8_t*)_P_ID2, _CONFIG.cpath, (uint8_t*)_CONFIG.user2, &idlen,
				_CONFIG.id_sys1, ASMA_SYSID_MAX, _CONFIG.pkg );
			if( res == TFP_OK ){
				ALOG("CI:TAG: Loaded prior user2 identity %s", _CONFIG.user2);
				_CONFIG.flag_has_user2 = 1;
			}
			else if( res == TFP_INTEGRITY ){
				ALOG("CI:ERR: TFP get user2 integrity error");
				ASCTI_Item_t item;
				MEMSET(&item, 0, sizeof(item));
				item.test = CTI_TEST_APPLICATIONTAMPERINGDETECTED;
				item.subtest = _SUBTEST_INTERNAL_PERSISTINTEGRITY;
				item.data3 = ERRORBASE+__LINE__;
				item.data3_type = ASCTI_DT_VRID;
				message_add( &item );

				// Overwrite it with blank data, so we don't keep hitting this issue
				TFP_Set_Ex( (uint8_t*)_P_ID2, _CONFIG.cpath, NULL,  0, _CONFIG.id_sys1, ASMA_SYSID_MAX, _CONFIG.pkg );
			}
		}
	}
	break;

	case SEED_23:
	{
		// Load our laststart data -- best effort
		uint32_t ls_len = sizeof(_CONFIG.laststart);
		uint32_t res = TFP_Get_Ex((uint8_t*)_P_LASTSTART, _CONFIG.cpath, (uint8_t*)&_CONFIG.laststart, 
			&ls_len, _CONFIG.id_sys1, ASMA_SYSID_MAX, _CONFIG.pkg );
		if( res == TFP_OK ){
			ALOG("CI:TAG: Loaded laststart");
			// Check version compatibility, may be older
			if( _CONFIG.laststart.version != _LASTSTART_VERSION ){
				// Throw it away; later we will save a newer one
				MEMSET( &_CONFIG.laststart, 0, sizeof(_CONFIG.laststart) );
			}

			// Check expiry timestamp; we will wipe it every 25 days
			if( _CONFIG.laststart.ts > 0 && (_CONFIG.laststart.ts + (60 * 60 * 24 * 25)) < time(0) ){
				ALOG("CI:TAG: Stale laststart, resetting");
				MEMSET( &_CONFIG.laststart, 0, sizeof(_CONFIG.laststart) );
			}
			if( _CONFIG.laststart.ts == 0 ) _CONFIG.laststart.ts = time(0);

			// NOT-MVP-TODO check ident, throw away if necessary
		}
		else if( res == TFP_INTEGRITY ){	
			ALOG("CI:ERR: TFP get laststart integrity error");
			ASCTI_Item_t item;
			MEMSET(&item, 0, sizeof(item));
			item.test = CTI_TEST_APPLICATIONTAMPERINGDETECTED;
			item.subtest = _SUBTEST_INTERNAL_PERSISTINTEGRITY;
			item.data3 = ERRORBASE+__LINE__;
			item.data3_type = ASCTI_DT_VRID;
			message_add( &item );

			// Overwrite it with blank data, so we don't keep hitting this issue
			TFP_Set_Ex( (uint8_t*)_P_LASTSTART, _CONFIG.cpath, NULL,  0, _CONFIG.id_sys1, ASMA_SYSID_MAX, _CONFIG.pkg );
		}
	}
	break;

	case SEED_24:
	{
		ALOG("CI:TAG: BOOTSTRAP: observations_init...");
		int r = observations_init(); 
		if( r == OBINIT_DEFSINTEGRITY ){
			ALOG("CI:ERR: unable to init obs - integrity");
			return error_report(ERRORBASE+__LINE__,0,_BOOTSTRAP_INTEGRITY);
		}
		else if( r != OBINIT_OK ){
			ALOG("CI:ERR: unable to init obs");
			return error_report(ERRORBASE+__LINE__,0,_BOOTSTRAP_SETUP);
		}
	}
	break;

	case SEED_25:
	{
		ALOG("CI:TAG: BOOTSTRAP: watchers_init...");
		if( watchers_init() != 0 ){
			ALOG("CI:ERR: unable to init watchers");
			return error_report(ERRORBASE+__LINE__,0,_BOOTSTRAP_SETUP);
		}
	}
	break;

	case SEED_26:
	{
		// thread out the startup thread
       		pthread_attr_t attr;
       		if( pthread_attr_init( &attr ) != 0 ){ ALOG("CI:ERR: Failed to attr_init"); return -1; }
        	if( pthread_attr_setdetachstate( &attr, PTHREAD_CREATE_DETACHED ) != 0 ){
                	ALOG("CI:ERR: Failed to set detached");
			return error_report(ERRORBASE+__LINE__,0,_BOOTSTRAP_SETUP);
		}
		uintptr_t tmp = (uintptr_t)flags_local;
        	if( pthread_create( &_startup_thread, &attr,
                	_startup_thread_handler, (void*)tmp ) != 0 ){
                	ALOG("CI:ERR: Failed to create startup thread");
			// Since the startup thread does a lot of integrity stuff, we are calling
			// this a security concern
			ASCTI_Item_t item;
			MEMSET(&item, 0, sizeof(item));
			item.test = CTI_TEST_SECURITYOPERATIONFAILED;
			item.subtest = _SUBTEST_INTERNAL_INTEGRITY;
			item.data3 = ERRORBASE+__LINE__;
			item.data3_type = ASCTI_DT_VRID;
			message_add( &item );
			return error_report(ERRORBASE+__LINE__,0,_BOOTSTRAP_INTEGRITY);
		}
	}
	break;

	case SEED_27:
	{
		// Indicate if this is non-prod keys
		if( _CONFIG.flag_nonprod > 0 ){
			ALOG("CI:TAG: NONPROD keys");
			ASCTI_Item_t item;
			MEMSET(&item, 0, sizeof(item));
			item.test = CTI_TEST_NONPRODKEYS;
			message_add( &item );
		}
	}

	case SEED_28:
	{
		// All good
		_CONFIG.flag_bootstrapped = 1;
		ALOG("CI:TAG: BOOTSTRAP: done");
		return _BOOTSTRAP_OK;
	}

	default:
	{
		ALOG("CI:ERR: fell off switch");
		ASCTI_Item_t item;
		MEMSET(&item, 0, sizeof(item));
		item.test = CTI_TEST_APPLICATIONTAMPERINGDETECTED;
		item.subtest = _SUBTEST_INTERNAL_INTEGRITY;
		item.data3 = ERRORBASE+__LINE__;
		item.data3_type = ASCTI_DT_VRID;
		message_add( &item );
		return _BOOTSTRAP_INTEGRITY;
	}

	  } // switch
	} // while
}


int bootstrap( const char appnom[ASMA_PKG_MAX], const char appver[ASMA_PKGVER_MAX],
	const char *rpath, const char *cpath, const uint8_t sysid[ASMA_SYSID_MAX], 
	void(*callback)(int,int,ASCTI_Item_t*), uint32_t flags_local )
{
	char path[ ASMA_PATH_MAX + sizeof(_F_CONF_AS) ];
	int fd;
	struct stat stt;
	uint8_t *config_1, *config_2;
	int res;

	// Control flow flattening
	uint32_t seed = SEED_START;
	while(1){
	  uint32_t s = _SEED_NEXT(seed);
	  switch(s)
	  {

	case SEED_1:
	{
		// Create path to config file (resource)
		size_t bplen = STRLEN(rpath);
		TFMEMCPY( path, rpath, bplen );
		TFMEMCPY( &path[bplen], _F_CONF_AS, sizeof(_F_CONF_AS) );
		path[bplen + sizeof(_F_CONF_AS)] = 0;
		ALOG("CI:TAG: Conf file=%s", path);
	}
	break;

	case SEED_2:
	{
		// Load our config file
		do { fd = OPEN(path,O_RDONLY,0); }
		while( fd == -1 && errno == EINTR );
	}
	break;

	case SEED_3:
	{
		if( fd == -1 ){
			ALOG("CI:ERR: opening config file");
			return error_report(ERRORBASE+__LINE__,0,_BOOTSTRAP_SETUP);
		}
	}
	break;

	case SEED_4:
	{
		if( FSTAT( fd, &stt ) != 0 ){ // NOTE: no EINTR
			ALOG("CI:ERR: Unable to stat config file");
			CLOSE(fd);
			return error_report(ERRORBASE+__LINE__,0,_BOOTSTRAP_SETUP);
		}
	}
	break;

	case SEED_5:
	{
		config_1 = (uint8_t*)MMAP( NULL, stt.st_size, PROT_READ,
			MAP_FILE|MAP_PRIVATE, fd, 0 );
		CLOSE(fd);
	}
	break;

	case SEED_6:
	{
		if( config_1 == MAP_FAILED ){
			ALOG("CI:ERR: unable to map config file");
			return error_report(ERRORBASE+__LINE__,0,_BOOTSTRAP_SETUP);
		}
	}
	break;

	case SEED_7:
	{
		config_2 = (uint8_t*)MMAP( NULL, stt.st_size, PROT_READ|PROT_WRITE,
			MAP_PRIVATE|MAP_ANON, -1, 0 );
	}
	break;

	case SEED_8:
	{
		if( config_2 == MAP_FAILED ){
			ALOG("CI:ERR: unable to map config mem");
			MUNMAP( config_1, stt.st_size );
			return error_report(ERRORBASE+__LINE__,0,_BOOTSTRAP_SETUP);
		}
	}
	break;

	case SEED_9:
	{
		TFMEMCPY( config_2, config_1, stt.st_size );
		MUNMAP( config_1, stt.st_size );
	}
	break;

	case SEED_10:
	{
		res = bootstrap_ex( appnom, appver, rpath, cpath, sysid, callback, flags_local, 
			config_2, (uint32_t)stt.st_size );
	}
	break;

	case SEED_11:
	{
		MUNMAP( config_2, stt.st_size );
	}
	break;

	case SEED_12:
	{
		return res;
	}

	default:
	{
		ALOG("CI:ERR: fell off switch");
		ASCTI_Item_t item;
		MEMSET(&item, 0, sizeof(item));
		item.test = CTI_TEST_APPLICATIONTAMPERINGDETECTED;
		item.subtest = _SUBTEST_INTERNAL_INTEGRITY;
		item.data3 = ERRORBASE+__LINE__;
		item.data3_type = ASCTI_DT_VRID;
		message_add( &item );
		return _BOOTSTRAP_INTEGRITY;
	}

	  } // switch
	} // while
}
