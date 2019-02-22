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

#ifndef _OB_DEBUGGER_INLINE_C_
#define _OB_DEBUGGER_INLINE_C_

#include <errno.h>
#include <stdint.h>

#include "as_ma_platform.h"
#include "ascti_tests.h"
#include "as_defs_flags.h"

#include "seed.h"

#define ERRORBASE_D 14000

#define WORK_MAX_OBD	3
static const uint32_t TRACERPID[] = {0x31cca7b8,0x3ed2683,0x5490e3ba,}; // "TracerPid:"

#define _S_OBD(nom) _decode((sizeof(nom)/4)-1,nom,work)

//
// NOTE: we run a coalesce cache for debugger detection; many parents (who call include this file)
// are one-shot, so it just works.  For things like the inotify_watcher, it's aware of caching and
// can periodically wipe it's own cache to 'reset' the detections.  This basically prevents us
// from sending out a flood of debugger alerts as soon as a debugger connects once.
//

#define D_CACHE_MAX 8
static uint64_t _d_cache[D_CACHE_MAX] = {0};
static uint8_t  _d_cache_ptr = 0;

static uint8_t _d_squelch_errors = 0;

__attribute__((always_inline))
static inline void observations_debugger( int looping, uint32_t *track )
{
	// TODO: factor in track

	uint32_t work[WORK_MAX_OBD];
	ASCTI_Item_t item;
	uint8_t buff[1024];
	ssize_t ret;
	int good = 0;
	int i;

	// BUGCATCH: we got the debugger checking happening before we were bootstrapped;
	// so check the order here
	if( _CONFIG.flag_debugger_go == 0 ){
		ALOG("CI:ERR: dbugger too early");
		error_report(ERRORBASE_D+__LINE__,0,0);
		return;
	}

	// Control flow flattening
	uint32_t seed = SEED_START;
	while(1){
		uint32_t start = _SEED_NEXT(seed);
		switch(start){

		case SEED_1:
			// BUGCATCH: we got into a debugger check before we were bootstrapped, which lead
			// to fd_self_status == 0, and that is a valid FD that lead to a false positive
			// Tracerpid hit.  So we need to catch that.
			if( _PLATFORM_CONFIG.fd_self_status > 0 ){
				do {
					ret = PREAD(_PLATFORM_CONFIG.fd_self_status, buff, sizeof(buff), 0);
				} while( ret == -1 && errno == EINTR );
			} else {
				errno = EBADFD;
				ret = -1; // this will error out, below
			}
			break;

		case SEED_2:
			if( ret == -1 ){
				// security operation failed
				int errno_ = errno;
				ALOG("CI:ERR: pread proc/self/status");
				MEMSET(&item, 0, sizeof(item));
				item.data3 = ERRORBASE_D+__LINE__;
				if( analytics_coalesce_check( _d_cache, D_CACHE_MAX, CTI_TEST_SECURITYOPERATIONFAILED, item.data3) == 0 ){
					error_report(ERRORBASE_D+__LINE__, errno_, 0);
                			item.test = CTI_TEST_SECURITYOPERATIONFAILED;
					item.data3_type = ASCTI_DT_VRID;
                			message_add( &item );
					analytics_coalesce_add( _d_cache, D_CACHE_MAX, &_d_cache_ptr,
						CTI_TEST_SECURITYOPERATIONFAILED, item.data3 );
				}
			}
			break;

		case SEED_3:
			if( ret != -1 ){
				for( i=0; i<ret; i++){
					if( buff[i] != 'T' ) continue;
					if( MEMCMP( &buff[i], _S_OBD(TRACERPID), 10 ) == 0 ){
						if( buff[i+10] == '\t' && buff[i+11] == '0' && buff[i+12] == '\n' )
							good++;
						break;
					}
				}
			}
			break;

		case SEED_4:
			if( ret != -1 && good == 0 ) {
				// TracerPid entry not found, or not untraced...it's bad either way
				ALOG("CI:ERR: DEBUGGER DETECTED (status tracerpid)");

				if( analytics_coalesce_check( _d_cache, D_CACHE_MAX, CTI_TEST_DEBUGINSTRUMENTATIONARTIFACT, 35) == 0 ){
					MEMSET(&item, 0, sizeof(item));
					item.test = CTI_TEST_DEBUGINSTRUMENTATIONARTIFACT;
					item.subtest = 35;
					message_add( &item );
					analytics_coalesce_add( _d_cache, D_CACHE_MAX, &_d_cache_ptr,
						CTI_TEST_DEBUGINSTRUMENTATIONARTIFACT, 35 );
				}
			}
			break;

		case SEED_5:
			good = 1;
			if( _PLATFORM_CONFIG.art_gdebuggeractive != NULL ){
				ALOG("CI:TAG: Debugger check (gdebuggeractive)");
				if( *(_PLATFORM_CONFIG.art_gdebuggeractive) > 0 ) good = 7; // this will trigger below
			}
			break;

		case SEED_6:
			if( good != 1 ){
				ALOG("CI:ERR: DEBUGGER DETECTED (art gDebuggerActive)");
				if( analytics_coalesce_check( _d_cache, D_CACHE_MAX, CTI_TEST_DEBUGINSTRUMENTATIONARTIFACT, 67) == 0 ){
					MEMSET(&item, 0, sizeof(item));
					item.test = CTI_TEST_DEBUGINSTRUMENTATIONARTIFACT;
					item.subtest = 67;
					message_add( &item );
					analytics_coalesce_add( _d_cache, D_CACHE_MAX, &_d_cache_ptr,
						CTI_TEST_DEBUGINSTRUMENTATIONARTIFACT, 67 );
				}
			}
			break;

		case SEED_7:
			good = 5;
			if( _PLATFORM_CONFIG.art_gdebuggeractive == NULL && _PLATFORM_CONFIG.art_isdebuggeractive != NULL ){
				ALOG("CI:TAG: Debugger check (isdebuggeractive)");
				int (*f)(void*) = (int(*)(void*))_PLATFORM_CONFIG.art_isdebuggeractive;
				if( f(NULL) > 0 ) good = 1;
			}
			break;

		case SEED_8:
			if( good != 5 ){
				ALOG("CI:ERR: DEBUGGER DETECTED (art isDebuggerActive)");
				if( analytics_coalesce_check( _d_cache, D_CACHE_MAX, CTI_TEST_DEBUGINSTRUMENTATIONARTIFACT, 67) == 0 ){
					MEMSET(&item, 0, sizeof(item));
					item.test = CTI_TEST_DEBUGINSTRUMENTATIONARTIFACT;
					item.subtest = 67;
					message_add( &item );
					analytics_coalesce_add( _d_cache, D_CACHE_MAX, &_d_cache_ptr,
						CTI_TEST_DEBUGINSTRUMENTATIONARTIFACT, 67 );
				}
			}
			break;


		case SEED_9:
			good = 4;
			if( _PLATFORM_CONFIG.dvm_dbg_isdebuggerconnected != NULL ){
				ALOG("CI:TAG: Debugger check (dvm isdebuggeractive)");
				int (*f)() = (int(*)())_PLATFORM_CONFIG.dvm_dbg_isdebuggerconnected;
				if( f() > 0 ) good = 2;
			}
			break;


		case SEED_10:
			if( good != 4 ){
				ALOG("CI:TAG: DEBUGGER DETECTED (dvm jdwp)");
				if( analytics_coalesce_check( _d_cache, D_CACHE_MAX, CTI_TEST_DEBUGINSTRUMENTATIONARTIFACT, 67) == 0 ){
					MEMSET(&item, 0, sizeof(item));
					item.test = CTI_TEST_DEBUGINSTRUMENTATIONARTIFACT;
					item.subtest = 67;
					message_add( &item );
					analytics_coalesce_add( _d_cache, D_CACHE_MAX, &_d_cache_ptr,
						CTI_TEST_DEBUGINSTRUMENTATIONARTIFACT, 67 );
				}
			}
			break;


		case SEED_11:
			good = 3;
//#ifdef __arm__
			//
			// Special handling for ARM on x86, only if none of the other stuff is available.
			// Not ideal, but is what it is.
			//

			//
			// 1.3: Android N needs this normally
			//

			//if( _PLATFORM_CONFIG.is_x86_emulating_arm > 0 &&
			if( 
 				_PLATFORM_CONFIG.art_gdebuggeractive == NULL &&
				_PLATFORM_CONFIG.art_isdebuggeractive == NULL &&
				_PLATFORM_CONFIG.dvm_dbg_isdebuggerconnected == NULL && 
				_PLATFORM_CONFIG.jc_vmd != NULL &&
				_PLATFORM_CONFIG.jm_idc != NULL
			){
				//
				// Attach a VM thread if necessary
				//
				JNIEnv *env = NULL;
				int r = (*_PLATFORM_CONFIG.vm)->GetEnv(_PLATFORM_CONFIG.vm, (void**)&env, JNI_VERSION_1_6);
				int do_detach = 0;
				if( r == JNI_EDETACHED ){
					if( (*_PLATFORM_CONFIG.vm)->AttachCurrentThread(_PLATFORM_CONFIG.vm, &env, NULL) != 0){
						ALOG("CI:ERR: Unable to attach debug thread");
						if( _d_squelch_errors == 0 )
							error_report(ERRORBASE_D+__LINE__,0,0);
						_d_squelch_errors++;
					} else {
						do_detach++;
						r = JNI_OK;
					}
				}
				if( r != JNI_OK ){
					ALOG("CI:ERR: debug thread vm attachment");
					if( _d_squelch_errors == 0 )
						error_report(ERRORBASE_D+__LINE__,r,0);
					_d_squelch_errors++;
				} else {
					// Now invoke method to check for debugger
					ALOG("CI:TAG: Debugger check (java isdebuggerconnected)");
					jboolean d = (*env)->CallStaticBooleanMethod( env, _PLATFORM_CONFIG.jc_vmd,
						_PLATFORM_CONFIG.jm_idc );
					if( (*env)->ExceptionCheck(env) ){
						if( _d_squelch_errors == 0 )
							error_report(ERRORBASE_D+__LINE__,0,0);
						_d_squelch_errors++;
						(*env)->ExceptionClear(env);
						// TODO: SEF/SOF?
					} else {
						if( d ) good = 5;
					}
				}

				if( looping == 0 && do_detach ){
					(*_PLATFORM_CONFIG.vm)->DetachCurrentThread(_PLATFORM_CONFIG.vm);
				}
			}
//#endif
			break;


		case SEED_12:
			if( good != 3 ){
				ALOG("CI:TAG: DEBUGGER DETECTED (vm jdwp)");
				if( analytics_coalesce_check( _d_cache, D_CACHE_MAX, CTI_TEST_DEBUGINSTRUMENTATIONARTIFACT, 67) == 0 ){
					MEMSET(&item, 0, sizeof(item));
					item.test = CTI_TEST_DEBUGINSTRUMENTATIONARTIFACT;
					item.subtest = 67;
					message_add( &item );
					analytics_coalesce_add( _d_cache, D_CACHE_MAX, &_d_cache_ptr,
						CTI_TEST_DEBUGINSTRUMENTATIONARTIFACT, 67 );
				}
			}
			break;


		case SEED_13:
			good = 2;
			// Detect if anyone NULL'd out the pointers we use
        		if( _PLATFORM_CONFIG.art_gdebuggeractive == NULL &&
                		_PLATFORM_CONFIG.art_isdebuggeractive == NULL &&
                		_PLATFORM_CONFIG.dvm_dbg_isdebuggerconnected == NULL
// Adjustment to allow java fallback for Android N
//#ifdef __arm__
//				&& (_PLATFORM_CONFIG.is_x86_emulating_arm > 0 && 
				&&	(_PLATFORM_CONFIG.jm_idc == NULL || _PLATFORM_CONFIG.jc_vmd == NULL )
//				   )
//#endif
 				){
				good = 4;
			}
			break;

		case SEED_14:
			if( good != 2 ){
				// Shouldn't happen, we call this an internal integrity issue
				ALOG("CI:ERR: NO DEBUGGER FUNCTIONS FOUND");
				if( analytics_coalesce_check( _d_cache, D_CACHE_MAX, 
					CTI_TEST_APPLICATIONTAMPERINGDETECTED, _SUBTEST_INTERNAL_INTEGRITY) == 0 ){
					MEMSET(&item, 0, sizeof(item));
					item.test = CTI_TEST_APPLICATIONTAMPERINGDETECTED;
					item.subtest = _SUBTEST_INTERNAL_INTEGRITY;
					item.data3 = ERRORBASE_D+__LINE__;
					item.data3_type = ASCTI_DT_VRID;
					message_add( &item );
					analytics_coalesce_add( _d_cache, D_CACHE_MAX, &_d_cache_ptr,
						CTI_TEST_APPLICATIONTAMPERINGDETECTED, _SUBTEST_INTERNAL_INTEGRITY );
				}
			}
			break;

		case SEED_15:
			// All done
			return;

		} // switch

		// loop in the while to the next seed
	} // while
}

#endif
