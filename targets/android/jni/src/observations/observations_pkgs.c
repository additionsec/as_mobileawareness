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

#include "as_ma_private.h"

#include "tf_cal.h"
#include "tf_pkcs7.h"
#include "tf_defs.h"

#include "as_defs_flags.h"
#include "ascti_tests.h"

#include "config.h"
#include "observations.h"

#define ERRORBASE 17000

static const uint8_t AOSP_PLATFORM_KEY[] = { 0x27,0x19,0x6e,0x38,0x6b,0x87,0x5e,0x76,0xad,0xf7,0x00,0xe7,0xea,0x84,0xe4,0xc6,0xee,0xe3,0x3d,0xfa };
static const uint8_t AOSP_TEST_KEY[] = { 0x61,0xED,0x37,0x7E,0x85,0xD3,0x86,0xA8,0xDF,0xEE,0x6B,0x86,0x4B,0xD8,0x5B,0x0B,0xFA,0xA5,0xAF,0x81 };


#define WORK_MAX	8
static const uint32_t SANDROID[] = {0x20c9bb8d,0x7bdc21bc,}; // "android"
static const uint32_t SPREFIX[] = {0x1e991ad,0x5a9821b6,}; // "ADDSEC"
static const uint32_t CNANDROIDDEBUG[] = {0x6fe396c3,0x46f60bdc,0x31ef9dee,0x17f403f6,0x5891e4ca,}; // "/CN=Android Debug"

static const uint32_t COMANDROIDVENDING[] = {0x7cc0ba8f,0x55d527b0,0x2cccb182,0x1bdb2fa8,0x54d9a69a,}; // "com.android.vending"
static const uint32_t COMAMAZONVENEZIA[] = {0x7cc0ba8f,0x5dd024b0,0x7c83b582,0x559f20bb,0x1afaa689,}; // "com.amazon.venezia"
static const uint32_t COMSECANDROIDAPPSAMSUNGAPPS[] = {0x7cc0ba8f,0x9d22ca2,0x2ccbbd9e,0x51d62fad,0x30c3b897,0x8cf3abe,0x2ec5bb92,0x6ddf20ba,}; // "com.sec.android.app.samsungapps"

#define _S(nom) _decode((sizeof(nom)/4)-1,nom,work)


#define SIG_PRIOR_MAX	64

typedef struct {
	uint16_t av_required;
	uint16_t av_count;
	uint16_t emm_required;
	uint32_t android[WORK_MAX];
	uint32_t prefix[WORK_MAX];

	uint32_t store1[WORK_MAX];
	uint32_t store2[WORK_MAX];
	uint32_t store3[WORK_MAX];

	uint16_t flag_seen_self : 1;
	uint16_t flag_seen_sys : 1;

	uint32_t sig_prior[SIG_PRIOR_MAX];
	uint16_t sig_prior_len[SIG_PRIOR_MAX];
	uint32_t sig_prior_ptr;

	// lowercase version of pkg:
	uint8_t  lc_pkg[ sizeof(_CONFIG.pkg) ];

} _app_scan_t;

#include "observations_item_common.inline.c"

static int _itoa(uint32_t n, char *s)
{
        int j = 0, i;
        char c;

        // convert to chars
        do { s[j++] = n % 10 + '0'; } while ((n/=10) > 0);
        s[j] = 0;

        // reverse()
        for( i=0, j=j-1; i<j; i++, j-- ){
                c = s[i];
                s[i] = s[j];
                s[j] = c;
        }
        return i;
}


#define _FLAG_DISABLED 1

__attribute__((always_inline))
static inline void _inspect_pkg( 
	_app_scan_t *state, 
	const char *pkg, 
	const uint8_t hash[TCL_MD5_DIGEST_SIZE], 
	uint8_t pkgflags )
{
	uint32_t flags=0;
	uint16_t id=0;
	int res = TFDefs_Hash_Lookup( &_CONFIG.defs_as, ASDEFS_SECTION_APPS, 
		(uint8_t*)hash, &flags, &id );

	if( res == TFDEFS_FOUND ){
		ALOG("CI:TAG: Found pkg %s flags=%x id=%d", pkg, flags, id);

		// Set up common item details
		ASCTI_Item_t item;
		ctiitem_setup_sys( &item );
		item.subtest = id;
		item.data1_type = ASCTI_DT_APPLICATION;
		item.data1 = (char *)pkg;
		item.data1_len = (uint16_t)STRLEN(pkg);

#ifndef UNITY
		if( flags & ASDEFS_FLAGS_AV ){
			if( pkgflags & _FLAG_DISABLED ){
				item.test = CTI_TEST_ANTIVIRUSDISABLED;
				message_add( &item );
			} else {
				item.test = CTI_TEST_ANTIVIRUSINSTALLED;
				// Don't report AV to backend
				item.flag_no_send = 1;
				message_add( &item );
				item.flag_no_send = 0;
				if( state != NULL && state->av_required == id )
					state->av_required = 0;
				if( state != NULL ) state->av_count++;
			}
		}

		if( flags & ASDEFS_FLAGS_EMM ){
			if( pkgflags & _FLAG_DISABLED ){
				item.test = CTI_TEST_EMMDISABLED;
				message_add( &item );
			} else {
				item.test = CTI_TEST_EMMINSTALLED;
				item.flag_no_send = 1;
				message_add( &item );
				item.flag_no_send = 0;
				if( state != NULL && state->emm_required == id )
					state->emm_required = 0;
			}
		}

#endif

		observations_item_common( ASDEFS_SECTION_APPS, &item, flags );
	}
}


#define CACHE_SIG_SIZE 16
static uint64_t _cache_sig[CACHE_SIG_SIZE];
static uint8_t _cache_sig_index;

// ApplicationInfo flags; they retain same values from 4.0 through 7.0
// http://androidxref.com/7.0.0_r1/xref/frameworks/base/core/java/android/content/pm/ApplicationInfo.java#131
// http://androidxref.com/4.0.4/xref/frameworks/base/core/java/android/content/pm/ApplicationInfo.java#104
#define APPFLAG_SYSTEM (1<<0)
#define APPFLAG_DEBUGGABLE (1<<1)
#define APPFLAG_HAS_CODE (1<<2)
#define APPFLAG_UPDATED_SYSTEM_APP (1<<7)
#define APPFLAG_EXTERNAL_STORAGE (1<<18)

__attribute__((always_inline))
static inline void _inspect_pkg_sig( 
	const char *pkg, 
	int appflags,
	const uint8_t pkghash[TCL_MD5_DIGEST_SIZE],
	const uint8_t as_sighash[TCL_MD5_DIGEST_SIZE], 
	const uint8_t *sig1, uint32_t sig1_len,
	const uint8_t sighash[TCL_SHA1_DIGEST_SIZE])
{
	uint32_t flags=0;
	uint16_t id=0;
	int res = TFDefs_Hash_Lookup( &_CONFIG.defs_as, ASDEFS_SECTION_SIGS, 
		(uint8_t*)as_sighash, &flags, &id );

	if( res == TFDEFS_FOUND ) {
		ALOG("CI:TAG: Found sig %s flags=%x id=%d appflags=%x sig[0]=%x", pkg, flags, id, appflags, sighash[0]);

		// TODO: should we be coalescing here? We may want to report all pkgs that
		// have affected sig, but coalesce will only report one

		if( id > 0 && _CONFIG.flag_analytics_coalesce > 0 &&
			analytics_coalesce_check( _cache_sig, CACHE_SIG_SIZE, flags, id ) == 1 )
		{
			ALOG("COALESE on %d/%d", flags, id);
			return;
		}

		// Android N: some AOSP signed apps are included in firmware, with the "restrict-update"
		// restriction.  They are technically false-positives to our AOSP check, but we don't
		// have an easy way to tell if they are "restrict-update" as it's not a flag in
		// package info.
		// https://android.googlesource.com/platform/frameworks/base/+/fdd241a%5E%21/#F0
		// It's a lot of hoops to actually check for restrict-update (use PackageParser, etc.);
		// instead, we are going to use a different heuristic: if it's AOSP signed, system app,
		// N or later, and has no code, then we don't report it. 
		//
		if( _PLATFORM_CONFIG.api >= 24 ) // 24 == Android N/7.0
		{
			if( MEMCMP(sighash, AOSP_TEST_KEY, sizeof(AOSP_TEST_KEY)) == 0 )
			{
				ALOG("CI:TAG: Flagged AOSP pkg");
				if( ( appflags & APPFLAG_SYSTEM ) > 0
					&& ( appflags & APPFLAG_HAS_CODE ) == 0 )
				{
					// Meets our criteria; ignore it
					ALOG("CI:TAG: Ignoring AOSP system no-code app %s", pkg);
					return;
				}
			}
		}


		// Set up common item details
		ASCTI_Item_t item;
		ctiitem_setup_sys( &item );
		item.subtest = id;

		item.data1_type = ASCTI_DT_APPLICATION;
		item.data1 = (char *)pkg;
		item.data1_len = (uint16_t)STRLEN(pkg);

		item.data2_type = ASCTI_DT_HASHSHA1;
		item.data2 = (uint8_t*)sighash;
		item.data2_len = TCL_SHA1_DIGEST_SIZE;

		observations_item_common( ASDEFS_SECTION_SIGS, &item, flags );

		if( id > 0 && _CONFIG.flag_analytics_coalesce > 0 ) {
			ALOG("ADDCOALESE on %d/%d", flags, id);
			analytics_coalesce_add( _cache_sig, CACHE_SIG_SIZE, &_cache_sig_index, flags, id );
		}
	}
}

void observations_pkgs_start( void **state )
{
	*state = MALLOC(sizeof(_app_scan_t));
	if( *state == NULL ){
		ALOG("CI:ERR: OOM inspect_apps_start");
		return;
	}
	MEMSET( *state, 0, sizeof(_app_scan_t) );

	_app_scan_t *ast = (_app_scan_t*)*state;
	ast->av_count = 0;

	// Configure our sig cache
	MEMSET(_cache_sig, 0, sizeof(_cache_sig));
	_cache_sig_index = 0;

	// NOT-MVP-TODO: fill these in from the configuration
	ast->av_required = 0;
	ast->emm_required = 0;

	// Decode our common strings
	uint32_t *work = ast->android;
	_S(SANDROID);
	work = ast->prefix;
	_S(SPREFIX);

	work = ast->store1;
	_S(COMANDROIDVENDING);
	work = ast->store2;
	_S(COMAMAZONVENEZIA);
	work = ast->store3;
	_S(COMSECANDROIDAPPSAMSUNGAPPS);

	// Copy and lowercase our package name
	TFMEMCPY( ast->lc_pkg, _CONFIG.pkg, sizeof(_CONFIG.pkg) );
	uint8_t *p;
	for( p = ast->lc_pkg; *p; ++p ){
		if( *p >='A' && *p <= 'Z' ) *p |= 0x60;
	}
}

void observations_pkgs_finish( void *state )
{
	if( state == NULL ) return;
	_app_scan_t *ast = (_app_scan_t*)state;

	// Set up common item details
	ASCTI_Item_t item;
	ctiitem_setup_sys( &item );

#ifndef UNITY
	if( ast->av_count == 0 ){
		// Didn't have any AV
		item.test = CTI_TEST_ANTIVIRUSNOTINSTALLED;
		item.flag_no_send = 1;
		message_add( &item );
		item.flag_no_send = 0;
	}
	if( ast->av_required > 0 ){
		// Didn't have required AV
		item.test = CTI_TEST_ANTIVIRUSREQUIREMENT;
		item.flag_no_send = 1;
		message_add( &item );
		item.flag_no_send = 0;
	}
	if( ast->emm_required > 0 ){
		// Didn't have required EMM
		item.test = CTI_TEST_EMMREQUIREMENT;
		message_add( &item );
	}
#endif

	if( ast->flag_seen_self == 0 ){
		// We didn't see ourselves in the pkg enumeration
		ctiitem_setup_app( &item );
		item.test = CTI_TEST_SECURITYEXPECTATIONFAILURE;
		item.subtest = 68;
		item.data3 = ERRORBASE+__LINE__;
		item.data3 = ASCTI_DT_VRID;
		message_add( &item );
	}

	if( ast->flag_seen_sys == 0 ){
		// We didn't see the system in the enumeration
		ctiitem_setup_sys( &item );
		item.test = CTI_TEST_SECURITYEXPECTATIONFAILURE;
		item.subtest = 69;
		item.data3 = ERRORBASE+__LINE__;
		item.data3 = ASCTI_DT_VRID;
		message_add( &item );
		error_report(ERRORBASE+__LINE__,0,0);
	}

	FREE(state);
	messages_flush();
}

void observations_pkg( 
	int vc, 
	void *state, 
	const char *pkg, 
	const uint8_t *sig1, uint32_t sig1_len,
        const uint8_t *sig2, uint32_t sig2_len, 
	uint8_t appflags, 
	int *is_us )
{
	uint8_t pkghash[TCL_MD5_DIGEST_SIZE];
	uint8_t sighash[TCL_SHA1_DIGEST_SIZE];
	uint32_t work[WORK_MAX];
	int is_sighashed = 0;

	_app_scan_t *ast = (_app_scan_t*)state;

	// Create package hash
	size_t pkg_sz = STRLEN(pkg);
	TCL_MD5_2( (uint8_t*)ast->prefix, 6, (uint8_t*)pkg, (uint32_t)pkg_sz, pkghash );

	_inspect_pkg( (_app_scan_t*)state, pkg, pkghash, 0 );

	// Process the sig
	if( sig1 != NULL && sig1_len > 0 ){
		// Get the CRC of the sig
		uint32_t crc = TCL_CRC32( sig1, sig1_len );

		// Have we seen this one before?
		int i;
		for( i=0; i<SIG_PRIOR_MAX; i++ ){
			if( ast->sig_prior[i] == 0 || (ast->sig_prior[i] == crc && 
				ast->sig_prior_len[i] == sig1_len) ) break;
		}

		// We use a prior sig cache to not keep re-checking the same sigs over and over,
		// which is a notable deal for system components that all have the same platform sig.
		//
		// TODO: this will only alert on the first pkg that has sig, not all pkgs that have sig.
		// That's good for system, but bad for other stuff.  It also should be subject to coalesce disable.
		//
		if( ast->sig_prior[i] == 0 || i >= SIG_PRIOR_MAX ){
			// Not found in our prior cache

			// Initial SHA1 of whole sig
			TCL_SHA1( sig1, sig1_len, sighash );
			is_sighashed++;

			// Now, MD5 of ADDSEC + that hash
			uint8_t assighash[TCL_MD5_DIGEST_SIZE];
			TCL_MD5_2( (uint8_t*)ast->prefix, 6, sighash, TCL_SHA1_DIGEST_SIZE, assighash );

			_inspect_pkg_sig( pkg, appflags, pkghash, assighash, sig1, sig1_len, sighash );

			// Overwrite at the pointer, then increment + wrap the pointer
			ast->sig_prior[ ast->sig_prior_ptr ] = crc;
			ast->sig_prior_len[ ast->sig_prior_ptr++ ] = sig1_len;
			if( ast->sig_prior_ptr >= SIG_PRIOR_MAX ) ast->sig_prior_ptr = 0;
		}
	}

	if( is_sighashed == 0 ){
		// Other things may send sighash without hashing, so we want to cleanly reset it
		MEMSET(sighash, 0, sizeof(sighash));
	}


	// Special check: is this us?
	if( pkg_sz == _CONFIG.pkg_sz && MEMCMP(pkg, ast->lc_pkg, pkg_sz) == 0 ){
		// It's us; do some signer reporting
		ast->flag_seen_self = 1;
		*is_us = 1;

		ASCTI_Item_t item;

		// We have to send our version code startup info
		// (normally sent in bootstrap.c, but we had to delay)
		_itoa(vc, _CONFIG.pkgver);
		ALOG("CI:VC: %s (%d)", _CONFIG.pkgver, vc);
		ctiitem_setup_app( &item );
		item.test = CTI_TEST_APPLICATIONINFO;
		item.data1 = _CONFIG.pkgver;
		item.data1_len = STRLEN(_CONFIG.pkgver);
		item.data1_type = ASCTI_DT_VERSTR;

		// Check laststart
		if( _CONFIG.laststart.v_vc != (uint32_t)vc && _CONFIG.flag_analytics_coalesce > 0 )
			item.flag_no_send = 1;
		else
			_CONFIG.laststart.v_vc = (uint32_t)vc;

        	message_add( &item );

		// Now send signer info
		ctiitem_setup_app( &item );

		char subject[TFS_PKCS7_SUBJECT_SIZE];

		if( sig1 == NULL || sig1_len == 0 ){
			item.test = CTI_TEST_APPLICATIONUNSIGNED;
		} else {
			item.test = CTI_TEST_APPLICATIONSIGNER;
			item.data1_type = ASCTI_DT_HASHSHA1;
			item.data1 = sighash;
			item.data1_len = sizeof(sighash);

			// May not actually be hashed; do it if needed
			if( is_sighashed == 0 ){
				// NOTE: prior logic checks sig1==NULL && sig1_len>0
				TCL_SHA1( sig1, sig1_len, sighash );
				is_sighashed++;
			}

			// Check laststart
			// NOTE: this will gate both signer & debug signed events at same time
			uint32_t *u32 = (uint32_t*)sighash;
			if( _CONFIG.laststart.signer1 == (*u32) && _CONFIG.flag_analytics_coalesce > 0 )
				item.flag_no_send = 1;
			else
				_CONFIG.laststart.signer1 = *u32;

			int ret = TFS_PKCS7_X509_Parse( (uint8_t*)sig1, sig1_len, NULL, NULL, subject, NULL );

			if( ret == 0 ){
				ALOG("CI:TAG: appsigner = '%s'", subject);
				item.data2_type = ASCTI_DT_X509S;
				item.data2 = subject;
				item.data2_len = STRLEN(subject);

				// Android special: Check if this is a debug cert
				if( STRSTR(subject, _S(CNANDROIDDEBUG)) != NULL ){
					// push prior message
					message_add( &item );

					item.test = CTI_TEST_APPLICATIONDEVELOPERSIGNED;
					// leave item.data1 & item.data2 intact
					// fall through to send, below
				}

			} else {
				ALOG("CI:ERR: TFS_X509_parse ret=%d", ret);
				error_report(ERRORBASE+__LINE__,ret,0);
			}
		}
		message_add( &item );

	}

	// Special check: is this the "android" system package?
	if( pkg_sz == 7 && MEMCMP(pkg, ast->android, 7) == 0 ){
		ast->flag_seen_sys = 1;

		ASCTI_Item_t item;
		ctiitem_setup_sys( &item );

		if( sig1 == NULL || sig1_len == 0 ){
			item.test = CTI_TEST_SYSTEMUNSIGNED;
			message_add( &item );
		} else {
			item.test = CTI_TEST_SYSTEMSIGNER;
			item.data1_type = ASCTI_DT_HASHSHA1;
			item.data1 = sighash;
			item.data1_len = sizeof(sighash);

			// May not actually be hashed; do it if needed
			// NOTE: sig1==NULL && sig1_len>0 checked above
			if( is_sighashed == 0 ){
				TCL_SHA1( sig1, sig1_len, sighash );
				is_sighashed++;
			}

			// Check laststart
			uint32_t *u32 = (uint32_t*)sighash;
			if( _CONFIG.laststart.signer2 == (*u32) && _CONFIG.flag_analytics_coalesce > 0 )
				item.flag_no_send = 1;
			else
				_CONFIG.laststart.signer2 = *u32;

			message_add( &item );

			// NOTE: the flag_no_send value gets inherited for these other reportings too:

			// SPECIAL: check if this is the AOSP platform key, but only
			// if it's not CM
			if( _PLATFORM_CONFIG.is_cyanogenmod == 0 && MEMCMP(sighash, AOSP_PLATFORM_KEY, sizeof(sighash)) == 0 ){
				// AOSP signed, trigger more alerts
				ALOG("CI:TAG: Platform is AOSP signed");

				item.data1 = NULL;
				item.data1_len = 0;

				// It's using AOSP test keys, that means it doesn't qualify as production
				// (by Google's definition)
				item.test = CTI_TEST_NONPRODUCTIONSYSTEMARTIFACT;
				item.subtest = _SUBTEST_AOSP_PLATFORM_SIGNED;
				message_add( &item );

				// Since this key is public, anyone can potentially sign a system app update
				// and get system privs
				item.test = CTI_TEST_OPENSYSTEMLOCALATTACKVECTOR;
				item.subtest = _SUBTEST_AOSP_PLATFORM_SIGNED;
				message_add( &item );
			}

		}
	}

#if 0
	// NOT-MVP-TODO: This is noise, and not catching actual store modifications ... so
	// disable and come back later to actually hash the APK, etc.
	// Special check: Is this a known store?
	if( (pkg_sz == 19 && MEMCMP(pkg, ast->store1, 19) == 0) || // google
		(pkg_sz == 18 && MEMCMP(pkg, ast->store2, 18) == 0) || // amazon
		(pkg_sz == 31 && MEMCMP(pkg, ast->store3, 31) == 0) ) // samsung
	{
		ALOG("CI:TAG: Store=%s", pkg);

		// Known store, report the sig
		ASCTI_Item_t item;
		ctiitem_setup_sys( &item );
		item.test = CTI_TEST_PROVISIONINGSIGNER;

		item.data1 = (void*)pkg;
		item.data1_len = pkg_sz;
		item.data1_type = ASCTI_DT_APPLICATION;

		if( sig1 != NULL && sig1_len > 0 ){
			item.data2_type = ASCTI_DT_HASHSHA1;
			item.data2 = sighash;
			item.data2_len = sizeof(sighash);
		}

		message_add( &item );
	}
#endif

}

