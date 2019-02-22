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

#ifndef _OB_INIT_INLINE_C_
#define _OB_INIT_INLINE_C_

#include <stdio.h>
#include <errno.h>

#include "as_ma_private.h"
#include "config.h"
#include "observations.h"

#include "tf_defs.h"

#include "ascti_tests.h"
#include "as_defs_flags.h"

#include "observations_debugger.inline.c"

#define ERRORBASE_OBI	16000


static TFDefs_CALLBACK_DEF(_callback){
        uint8_t digest[TCL_SHA256_DIGEST_SIZE];
        TCL_SHA256( data, len, digest );

        int i;
#ifdef SIGN_WITH_RSA
        for( i=0; i<KEYS_RSA_ROOT_CNT; i++ ){
                int err = 0;
                int res = TCL_RSA_Verify( KEYS_RSA_ROOT[i], 292, digest, header->sig_rsa, &err );
                if( res == TCL_VERIFY_OK ){
                        ALOG("CI:TAG: DEFS: verified with key %d rsa", i);
                        ASCTI_Item_t item;
                        MEMSET( &item, 0, sizeof(item) );
                        item.test = CTI_TEST_SIGNINGKEY;
                        item.subtest = 2;
                        item.data1_type = ASCTI_DT_RAWBINARY;
                        item.data1 = KEYS_RSA_ROOT[i];
                        item.data1_len = 292;
                        message_add( &item );
                        return TFDEFS_LOAD_OK;
                }
                else if( res != TCL_VERIFY_FAIL ){
                        ALOG("CI:ERR: DEFS: verify rsa res=%d err=%d", res, err);
                        error_report(ERRORBASE_OBI+__LINE__, err, 0);
                }
        }
#else
        for( i=0; i<KEYS_ECC_ROOT_CNT; i++ ){
                int err = 0;
                int res = TCL_ECC_Verify( KEYS_ECC_ROOT[i], digest, header->sig_ecc, &err );
                if( res == TCL_VERIFY_OK ){
                        ALOG("CI:TAG: DEFS: verified with key %d ecc", i);
                        ASCTI_Item_t item;
                        MEMSET( &item, 0, sizeof(item) );
                        item.test = CTI_TEST_SIGNINGKEY;
                        item.subtest = 2;
                        item.data1_type = ASCTI_DT_RAWBINARY;
                        item.data1 = KEYS_ECC_ROOT[i];
                        item.data1_len = 64;
                        message_add( &item );
                        return TFDEFS_LOAD_OK;
                }
                else if( res != TCL_VERIFY_FAIL ){
                        ALOG("CI:ERR: DEFS: verify ecc res=%d err=%d", res, err);
                        error_report(ERRORBASE_OBI+__LINE__, err, 0);
                }
        }
#endif
        ALOG("CI:ERR: DEFS: not verified");
        return TFDEFS_LOAD_ERR_SIGN;
}



__attribute__((always_inline))
static inline int observations_init()
{
#if 0
	char path[ ASMA_PATH_MAX + 16 ] = {0};
	int pathlen = (int)STRLEN((char*)_CONFIG.rpath);
	MEMCPY( path, _CONFIG.rpath, pathlen + 1 );
	path[pathlen] = '/';

	// Load the AS defs file
	MEMCPY(&path[pathlen + 1], _F_DEFS_AS, STRLEN(_F_DEFS_AS)+1);
	ALOG("CI:TAG: as defs path=%s", path);
	int ret = TFDefs_Load( &_CONFIG.defs_as, path, _KEYS, DEFSIDENT );
#endif


#ifdef UNITY
	//
	// Direct/Unity passes defs as a memory array
	//
	const uint8_t *defs_data = _PLATFORM_CONFIG.defs;
	uint32_t defs_data_length = _PLATFORM_CONFIG.defs_len;
	if( defs_data == NULL ){
		ALOG("CI:ERR: defs is NULL");
		return error_report(ERRORBASE_OBI+__LINE__,0,-1);
	}
#else
	//
	// Normal Android retrieves the defs from APK assets/
	//
	AAsset *a_def = AAssetManager_open( _PLATFORM_CONFIG.am, "as.def", AASSET_MODE_BUFFER );
	if( a_def == NULL ){
		ALOG("CI:ERR: aasset_mgr open as.def");
		return error_report(ERRORBASE_OBI+__LINE__,0,-1);
	}

	const uint8_t *defs_data = (uint8_t*)AAsset_getBuffer( a_def );
	if( defs_data == NULL ){
		ALOG("CI:ERR: asset_getbuf");
		AAsset_close(a_def);
		return error_report(ERRORBASE_OBI+__LINE__,0,-1);
	}
	uint32_t defs_data_length = (uint32_t)(AAsset_getLength( a_def ) & 0xffffffff);
#endif

	ALOG("CI:TAG: loading defs from mem (len=%d)", defs_data_length);
	// NOTE: Load_From_Mem takes a const to defs_data, and will clone it internally in memory
	int ret = TFDefs_Load_From_Mem( &_CONFIG.defs_as, defs_data, defs_data_length, _callback, DEFSIDENT );

#ifndef UNITY
	AAsset_close(a_def);
#endif

	if( ret == TFDEFS_LOAD_ERR_SIGN ){
                // Signature problem, this is tampering
                ALOG("CI:ERR: Failed to load as defs - signing related");
                ASCTI_Item_t item;
		MEMSET(&item, 0, sizeof(item));
                item.test = CTI_TEST_APPLICATIONTAMPERINGDETECTED;
                item.subtest = _SUBTEST_INTERNAL_DEFSIG;
		item.data3_type = ASCTI_DT_VRID;
		item.data3 = ERRORBASE_OBI+__LINE__;
                message_add( &item );
                return -1;

        } else if(ret != TFDEFS_LOAD_OK ){
                ALOG("CI:ERR: Failed to load as defs; errno=%d", errno);
		return error_report(ERRORBASE_OBI+__LINE__,errno,-1);
        }

        // Good time to do a debugger check
        observations_debugger(0, &_CONFIG.track_debug);

	// Confirm we have all the necessary sections
	uint8_t sections[] = { ASDEFS_SECTION_APPS, ASDEFS_SECTION_FILES,  ASDEFS_SECTION_SIGS,
		ASDEFS_SECTION_LIBS, ASDEFS_SECTION_ENV, ASDEFS_SECTION_PROPS,
		ASDEFS_SECTION_PROXY, ASDEFS_SECTION_HOOKS, ASDEFS_SECTION_SYMBOLS };
	int i;
	for( i=0; i<=8; i++){
		if( TFDefs_Has_Section( &_CONFIG.defs_as, sections[i] ) != TFDEFS_FOUND ){
			ALOG("CI:ERR: Failed to find section %d", sections[i]);
			return error_report(ERRORBASE_OBI+__LINE__,sections[i],-1);
		}
	}

	// All good
	return 0;
}

#endif
