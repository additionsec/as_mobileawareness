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

#include "as_ma_private.h"
#include "ascti_tests.h"
#include "as_defs_flags.h"

#include "tf_cal.h"

#include "observations_debugger.inline.c"

#define ERRORBASE_OBINIT	57000


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
			error_report(ERRORBASE_OBINIT+__LINE__, err, 0);
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
			error_report(ERRORBASE_OBINIT+__LINE__, err, 0);
		}
	}
#endif
	ALOG("CI:ERR: DEFS: not verified");
	return TFDEFS_LOAD_ERR_SIGN;
}

__attribute__((always_inline))
static inline int observations_init()
{
	int ret;
	if( _PLATFORM_CONFIG.defs != NULL ){
        	ALOG("CI:TAG: as defs load from mem");
        	ret = TFDefs_Load_From_Mem( &_CONFIG.defs_as, _PLATFORM_CONFIG.defs, 
			_PLATFORM_CONFIG.defs_len, _callback, DEFSIDENT );
	} else {
      		uint8_t path[ ASMA_PATH_MAX + 16 ] = {0};
        	int pathlen = (int)STRLEN((char*)_CONFIG.rpath);
        	MEMCPY( path, _CONFIG.rpath, pathlen + 1 );
        	path[pathlen] = '/';

        	// Load the AS defs file
        	MEMCPY(&path[pathlen + 1], _F_DEFS_AS, STRLEN(_F_DEFS_AS)+1);
        	ALOG("CI:TAG: as defs path=%s", path);
        	ret = TFDefs_Load( &_CONFIG.defs_as, (char*)path, _callback, DEFSIDENT );
	}

	if( ret == TFDEFS_LOAD_ERR_SIGN ){
		// Signature problem, this is tampering
                ALOG("CI:ERR: Failed to load as defs - signing related");
		ASCTI_Item_t item;
		MEMSET(&item, 0, sizeof(item));
		item.test = CTI_TEST_APPLICATIONTAMPERINGDETECTED;
		item.subtest = _SUBTEST_INTERNAL_DEFSIG;
		item.data3_type = ASCTI_DT_VRID;
		item.data3 = ERRORBASE_OBINIT+__LINE__;
		message_add( &item );
                return OBINIT_DEFSINTEGRITY;

	} else if(ret != TFDEFS_LOAD_OK ){
                ALOG("CI:ERR: Failed to load as defs (ret=%d)", ret);
		return error_report(ERRORBASE_OBINIT+__LINE__,ret,OBINIT_DEFSFORMAT);
        } else {
		ALOG("CI:TAG: Loaded defs ver=%d", TFDefs_Version( &_CONFIG.defs_as ));
	}

	// Good time to do a debugger check
	observations_debugger(0, &_CONFIG.track_debug);

        // Make sure we have our intended sections
	uint8_t sections[] = { ASDEFS_SECTION_FILES, ASDEFS_SECTION_SYMBOLS, ASDEFS_SECTION_LIBS,
		ASDEFS_SECTION_HOOKS, ASDEFS_SECTION_ENV, ASDEFS_SECTION_PROXY,
		ASDEFS_SECTION_APPROVEDDYLIBS };
	int i;
	for( i=0; i<=6; i++ ){
        	if( TFDefs_Has_Section( &_CONFIG.defs_as, sections[i] ) != TFDEFS_FOUND ){
                	ALOG("CI:ERR: Failed to find section %d", sections[i]); 
			return error_report(ERRORBASE_OBINIT+__LINE__,0,OBINIT_DEFSFORMAT); }
	}

	// All good
	return OBINIT_OK;
}

#endif
