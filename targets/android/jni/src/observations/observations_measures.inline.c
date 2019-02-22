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

#ifndef _OB_MEASURE_INLINE_C_
#define _OB_MEASURE_INLINE_C_

#include <errno.h>
#include <sys/stat.h>
#include <dlfcn.h>

#include "as_ma_platform.h"

#include "tf_cal.h"
#include PLATFORM_H

#define ERRORBASE_M 20000

#include "keys.inline.c"

static void _m_sof(uint32_t vrid)
{
	ASCTI_Item_t item;
	ctiitem_setup_app( &item );
	item.test = CTI_TEST_SECURITYOPERATIONFAILED;
	item.subtest = _SUBTEST_INTERNAL_INTEGRITY;
	item.data3 = vrid;
	item.data3_type = ASCTI_DT_VRID;
	message_add( &item );
}

__attribute__((always_inline))
static inline void observations_measures()
{
	int ret, fd;
	ASCTI_Item_t item;
	struct stat stt;
	uint8_t digest[ TCL_SHA256_DIGEST_SIZE ];
	uint32_t *u32 = (uint32_t*)digest;
	void *apk_mem;

	// Locate the path to the host .so
        Dl_info dli;
	char *ptr = _PLATFORM_CONFIG.asmalib;
	if( _PLATFORM_CONFIG.asmalib[0] == 0 ){
		ALOG("CI:ERR: missing asmalib path, falling back to dladdr");
		error_report(ERRORBASE_M+__LINE__,0,0);

	        if( dladdr( observations_libs, &dli ) == 0 ){
       	        	ALOG("CI:ERR: Unable to dladdr self");
			_m_sof(ERRORBASE_M+__LINE__);
       	        	return;
		}
		// NOTE: this may be a relative name on some platforms, which is
		// why we prefer using the value found via the libs walk over
		// what dladdr reports.
		ptr = (char*)dli.dli_fname;
	}

	const char 	 *L_NOMS[] = { _PLATFORM_CONFIG.apk, ptr };
	const uint16_t  L_SUBTESTS[] = { _SUBTEST_APPMEASURE_APK, _SUBTEST_APPMEASURE_FILE };
	uint32_t *L_M[] = { &_CONFIG.laststart.measure4, &_CONFIG.laststart.measure1 };

	int i;
	for( i=0; i<2; i++ ){

		ctiitem_setup_app( &item );

		//if( _PLATFORM_CONFIG.apk[0] == 0 ){
		if( L_NOMS[i][0] == 0 ){
			ALOG("CI:ERR: Measure path %d not defined", i);
			_m_sof(ERRORBASE_M+__LINE__);
			error_report(ERRORBASE_M+__LINE__,i,0);
			continue;
		}

		//do { fd = OPENAT( AT_FDCWD, _PLATFORM_CONFIG.apk, O_RDONLY, 0 ); }
		do { fd = OPENAT( AT_FDCWD, L_NOMS[i], O_RDONLY, 0 ); }
		while( fd == -1 && errno == EINTR );
		if( fd == -1 ){
			error_report(ERRORBASE_M+__LINE__,errno,0);
			ALOG("CI:ERR: open measure '%s'", L_NOMS[i]);
			_m_sof(ERRORBASE_M+__LINE__);
			continue;
		}

		ret = FSTAT( fd, &stt );
		if( ret == -1 ){
			error_report(ERRORBASE_M+__LINE__,errno,0);
			ALOG("CI:ERR: fstat on measure '%s'", L_NOMS[i]);
			do { ret = CLOSE(fd); } while( ret == -1 && errno == EINTR );
			_m_sof(ERRORBASE_M+__LINE__);
			continue;
		}

		apk_mem = MMAP( NULL, stt.st_size, PROT_READ, MAP_FILE|MAP_SHARED, fd, 0 );
		do { ret = CLOSE(fd); } while( ret == -1 && errno == EINTR );
		if( apk_mem == MAP_FAILED ){
			error_report(ERRORBASE_M+__LINE__,errno,0);
			ALOG("CI:ERR: Unable to mmap measure %d", i);
			_m_sof(ERRORBASE_M+__LINE__);
			return;
		}

		TCL_SHA256( apk_mem, stt.st_size, digest );
		item.test = CTI_TEST_APPLICATIONMEASUREMENT;
		item.subtest = L_SUBTESTS[i];
		item.data1 = digest;
		item.data1_len = sizeof(digest);
		item.data1_type = ASCTI_DT_HASHSHA256;
		item.data2 = (void*)L_NOMS[i];
		item.data2_len = STRLEN(L_NOMS[i]);
		item.data2_type = ASCTI_DT_FILE;

		//if( _CONFIG.laststart.measure1 == *u32 && _CONFIG.flag_analytics_coalesce > 0 ){
		if( *(L_M[i]) == *u32 && _CONFIG.flag_analytics_coalesce > 0 ){
			item.flag_no_send = 1;
		} else {
			//_CONFIG.laststart.measure1 = *u32;
			*(L_M[i]) = *u32;
		}
		message_add( &item );

		if( i == 0 ){
			// TODO: parse zip and get other stuff while it's in mem?
		}

#if defined(BUILD_STANDALONE) || defined(BUILD_MEASURABLE)
		if( i == 1 ){
			uint32_t *p = (uint32_t*)_SA_DIGEST; // Offset/len to digest
			if( p[0] > stt.st_size ){
				ALOG("CI:ERR: Standalone sig offset issue");
				error_report(ERRORBASE+__LINE__,0,0);
				ctiitem_setup_app( &item );
				item.test = CTI_TEST_APPLICATIONTAMPERINGDETECTED;
				item.subtest = 1;
				item.data3_type = ASCTI_DT_VRID;
				item.data3 = ERRORBASE+__LINE__;
				message_add( &item );
			} else {
				// Have to re-hash the APK up to the offset
				TCL_SHA256( apk_mem, p[0], digest );

				// TODO: have to run this through root keys tlv
				uint8_t *sig = (uint8_t*)&p[1];
				if( TCL_ECC_Verify(KEYS_ECC_ROOT[0], digest, sig, NULL) != TCL_VERIFY_OK ){
					ALOG("CI:ERR: Standlone sig failed");
					item.test = CTI_TEST_APPLICATIONTAMPERINGDETECTED;
					item.subtest = 104;
					item.data3_type = ASCTI_DT_VRID;
					item.data3 = ERRORBASE+__LINE__;
					message_add( &item );
				} else {
					ALOG("CI:TAG: Standalone sig verified");
				}
			}
		}
#endif

		MUNMAP( apk_mem, stt.st_size );
	} // for loop
}

#endif
