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

#ifndef _OBS_STARTUP_INLINE_H_
#define _OBS_STARTUP_INLINE_H_

#include <stdio.h>
#include <sys/utsname.h>
#include <sys/stat.h>
#include <sys/statfs.h>

#include "as_ma_private.h"
#include "config.h"
#include "observations.h"

#include "tf_cal.h"

#include "as_cti.h"
#include "ascti_tests.h"
#include "as_defs_flags.h"

#define ERRORBASE_OS 18000

// Doesn't seem to be defined in Android 32-bit platform headers
#ifndef ST_RDONLY
#define ST_RDONLY 0x0001
#endif


#define WORK_MAX_OS 8

static const uint32_t ROBUILDFINGERPRINT[] = {0x3083ba9e,0xf9e20b5,0x368ab9c6,0x158127fd,0x2e8aa9d4,0x65eb4a8e,}; // "ro.build.fingerprint"
static const uint32_t ROBUILDDESCRIPTION[] = {0x3083ba9e,0xf9e20b5,0x2b86bbc6,0x89632f9,0x299cbcd6,0x62fd5f8c,}; // "ro.build.description"
static const uint32_t ROBUILDVERSIONRELEASE[] = {0x3083ba9e,0xf9e20b5,0x2a86a9c6,0x17903be9,0x3490ae9c,0x1a822ca3,0x5defc3fa,}; // "ro.build.version.release"
static const uint32_t ROPRODUCTMODEL[] = {0x2283ba9e,0xc9626b2,0x36c5ad8c,0x9d932bf,0x46bcd5e4,}; // "ro.product.model"
static const uint32_t ROHARDWARE[] = {0x3a83ba9e,0x16963ba1,0x418eb69d,}; // "ro.hardware"
static const uint32_t SYSTEM[] = {0x21d4a6c3,0x55c830e9,0x2b5cfb4,}; // "/system/"
static const uint32_t INITSVCADBD[] = {0x26c4bb85,0x1ec33bf5,0x2bdaa586,0x78a35ebe,}; // "init.svc.adbd"

#define _S_OS(nom) _decode((sizeof(nom)/4)-1,nom,work)


#define ITEMSET(t, typ, st) do { \
        MEMSET( &item, 0, sizeof(item) );\
        item.test = t; \
        item.subtest = st; \
        item.type = typ; \
        } while(0)

#define ITEMDATA1(d1typ,d1len,d1) do { \
        item.data1_type = d1typ; \
        item.data1_len = d1len; \
        item.data1 = d1; \
        } while(0)

#define ITEMDATA2(d2typ,d2len,d2) do { \
        item.data2_type = d2typ; \
        item.data2_len = d2len; \
        item.data2 = d2; \
        } while(0)

#include "observations_properties.inline.c"
#include "observations_files.inline.c"
#include "observations_debugger.inline.c"
#include "observations_libs.inline.c"
#include "observations_hooks.inline.c"
#include "observations_env.inline.c"
#include "observations_measures.inline.c"

#include "seed.h"

__attribute__((always_inline))
static inline void observations_startup(uint32_t flags_local)
{
	uint32_t work[WORK_MAX_OS];
	ASCTI_Item_t item;

        //uint32_t *u32 = (uint32_t*)digest;
	uint32_t u32;
	char prop_value[PROP_VALUE_MAX];
        struct statfs stf;
	int r;

	uint32_t seed = SEED_START;
	while(1){
	  uint32_t s = _SEED_NEXT(seed);
	  switch(s){

	case SEED_1:
		// NOTE: if the fingerprint exceeds 92 chars, it won't return anything.
		// We've seen the API 16 emulator meet this criteria.  :/
		// If that happens, let's try to fall back onto the description
		r = property_get(_S_OS(ROBUILDFINGERPRINT), prop_value);
		if( r <= 0 ) r = property_get(_S_OS(ROBUILDDESCRIPTION), prop_value);
		break;

	case SEED_2:
		if( r > 0 ){
			u32 = TCL_CRC32( (uint8_t*)prop_value, r );

			ITEMSET( CTI_TEST_SYSTEMFIRMWAREINFO, ASCTI_OBT_SYSTEM, 0 );
			ITEMDATA1( ASCTI_DT_VERSTR, r, prop_value );

			if( _CONFIG.laststart.firmware == (u32) && _CONFIG.flag_analytics_coalesce > 0 )
       	                 	item.flag_no_send = 1;
       	         	else
                        	_CONFIG.laststart.firmware = u32;

			message_add( &item );

			if( r >= sizeof(_CONFIG.err_fp) ) r = sizeof(_CONFIG.err_fp) - 1;
			MEMCPY( &_CONFIG.err_fp, prop_value, r );
		}
		else error_report(ERRORBASE_OS+__LINE__,0,0);
		break;

	case SEED_3:
		r = property_get(_S_OS(ROBUILDVERSIONRELEASE), prop_value);
		break;

	case SEED_4:
		if( r > 0 ){
			u32 = TCL_CRC32( (uint8_t*)prop_value, r );

			ITEMSET( CTI_TEST_SYSTEMOSINFO, ASCTI_OBT_SYSTEM, 0 );
			ITEMDATA1( ASCTI_DT_VERSTR, r, prop_value );

			if( _CONFIG.laststart.os == (u32) && _CONFIG.flag_analytics_coalesce > 0 )
                        	item.flag_no_send = 1;
                	else
                        	_CONFIG.laststart.os = u32;

			message_add( &item );
		}
		else error_report(ERRORBASE_OS+__LINE__,0,0);
		break;

	case SEED_5:
		observations_hooks(1);
		break;

	case SEED_6:
		r = property_get(_S_OS(ROPRODUCTMODEL), prop_value);
		break;

	case SEED_7:
		if( r <= 0 ) r = property_get(_S_OS(ROHARDWARE), prop_value);
		break;

	case SEED_8:
		if( r > 0 ){
			u32 = TCL_CRC32( (uint8_t*)prop_value, r );

			ITEMSET( CTI_TEST_SYSTEMHARDWAREINFO, ASCTI_OBT_SYSTEM, 0 );
			ITEMDATA1( ASCTI_DT_MODEL, r, prop_value );

			if( _CONFIG.laststart.hardware == (u32) && _CONFIG.flag_analytics_coalesce > 0 )
                        	item.flag_no_send = 1;
                	else
                        	_CONFIG.laststart.hardware = u32;

			message_add( &item );
		}
		else error_report(ERRORBASE_OS+__LINE__,0,0);
		break;

	case SEED_9:
		r = property_get(_S_OS(INITSVCADBD), prop_value);
		if( r > 0 && prop_value[0] == 'r' ){
			// ADBd is running
			ITEMSET( CTI_TEST_ADBDRUNNING, ASCTI_OBT_SYSTEM, 0 );
			message_add( &item );
			_PLATFORM_CONFIG.adbd = 1;
		}
		break;

	case SEED_10:
		if( flags_local & FLAG_INSTRUMENTATION ){
			ITEMSET( CTI_TEST_DEBUGINSTRUMENTATIONARTIFACT, ASCTI_OBT_APP, 60 );
			message_add( &item );
		}
		break;

	case SEED_11:
		observations_properties();
		break;

	case SEED_12:
		if( flags_local & FLAG_DEBUGMODE ){
			ITEMSET( CTI_TEST_DEBUGINSTRUMENTATIONARTIFACT, ASCTI_OBT_APP, 61 );
			message_add( &item );
		}
		break;

	case SEED_13:
		if( flags_local & FLAG_DEBUGGABLE ){
			ITEMSET( CTI_TEST_OPENAPPLICATIONLOCALATTACKVECTOR, ASCTI_OBT_APP, 62 );
			message_add( &item );
		}
		break;

	case SEED_14:
		// DEPRECATED
		break;

	case SEED_15:
		observations_files(ASDEFS_SECTION_FILES);
		break;

	case SEED_16:
		observations_env();
		break;

	case SEED_17:
		observations_debugger(0, &_CONFIG.track_debug);
		break;

	case SEED_18:
		// DEPRECATED
		break;

	case SEED_19:
		observations_libs();
		break;

	case SEED_20:
		// DEPRECATED
		break;

	case SEED_21:
		observations_java();
		break;

	case SEED_22:
		// DEPRECATED
		break;

	case SEED_23:
		// DEPRECATED
		break;

	case SEED_24:
        	// Check if root FS is mounted RO or RW
		// NOTE: mount info is only present in 2.6.36 kernels and later, which is
		// approx Honeycomb.  So this will fail on Gingerbread and prior.
		//
		// ICS started with approx Linux kernel 3.0.1.

        	if( STATFS("/", &stf) == 0 ){
               		if( (stf.f_flags & ST_RDONLY) == 0 ){
                        	ALOG("CI:TAG: MOUNTRW /");
                        	ITEMSET( CTI_TEST_SECURITYEXPECTATIONFAILURE, ASCTI_OBT_SYSTEM, 42 );
				item.data3 = ERRORBASE_OS+__LINE__;
				item.data3_type = ASCTI_DT_VRID;
                        	message_add( &item );
                	}
        	} else {
                	ALOG("CI:ERR: statfs");
                	error_report( ERRORBASE_OS+__LINE__, errno, -3);
        	}
		break;

	case SEED_25:
        	// Check if /system/ FS is mounted RO or RW
        	if( STATFS(_S_OS(SYSTEM), &stf) == 0 ){
                	if( (stf.f_flags & ST_RDONLY) == 0 ){
                        	ALOG("CI:TAG: MOUNTRW /system/");
                        	ITEMSET( CTI_TEST_SECURITYEXPECTATIONFAILURE, ASCTI_OBT_SYSTEM, 66 );
				item.data3 = ERRORBASE_OS+__LINE__;
				item.data3_type = ASCTI_DT_VRID;
                        	message_add( &item );
                	}
        	} else {
                	ALOG("CI:ERR: statfs");
                	error_report( ERRORBASE_OS+__LINE__, errno, -3);
        	}
		break;

	case SEED_26:
		// DEPRECATED
		break;

	case SEED_27:
		observations_measures();
		break;

	case SEED_28:
		return;

	default:
		ALOG("CI:ERR: ran off switch");
		ASCTI_Item_t item;
		ctiitem_setup_app( &item );
		item.test = CTI_TEST_APPLICATIONTAMPERINGDETECTED;
		item.subtest = _SUBTEST_INTERNAL_INTEGRITY;
		item.data3_type = ASCTI_DT_VRID;
		item.data3 = ERRORBASE_OS+__LINE__;
		message_add( &item );
		return;

	  } // switch
	} // while
}

#endif
