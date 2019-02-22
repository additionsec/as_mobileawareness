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

#include <stdint.h>
#include <pthread.h>

#include "as_ma_private.h"
#include "as_cti.h"
#include "observations/checkhook.h"

#include "analytics_platform.inline.c"

#define ERRORBASE	38000

static int _cache_lock = 0;

int analytics_coalesce_check( uint64_t cache[], uint8_t cache_count, uint32_t flags, uint16_t id )
{
	ASSERT(cache);

	// NOT-MVP-TODO: this doesn't separate flags into individual entries, which means
	// flag=(X|Y) and flag=(X) are considered different, even tho X part of flag=(X|Y)
	// may have already been reported.

	// Construct match value
	uint64_t match = flags;
	match = (match << 32) | id;
	if( match == 0 ) return 0;

	// Mutex around all cache access
        while( !__sync_bool_compare_and_swap( &_cache_lock, 0, 1 ) ){}
        __sync_synchronize();

	// Search for existing match
	int i, res=0;
	for( i=0; i<cache_count; i++ ){
		if( cache[i] == 0 ) break;
		if( cache[i] == match ){ res = 1; break; }
	}

	// Unlock mutex
        __sync_synchronize();
        _cache_lock = 0;

	return res;
}


void analytics_coalesce_add( uint64_t cache[], uint8_t cache_count, uint8_t *cache_index,
	uint32_t flags, uint16_t id )
{
	ASSERT(cache);
	ASSERT(cache_index);
	ASSERT(*cache_index < cache_count);

	// NOT-MVP-TODO: this doesn't separate flags into individual entries, which means
	// flag=(X|Y) and flag=(X) are considered different, even tho X part of flag=(X|Y)
	// may have already been reported.

	// Construct match value
	uint64_t match = flags;
	match = (match << 32) | id;
	if( match == 0 ) return;

	// Mutex around all cache access
        while( !__sync_bool_compare_and_swap( &_cache_lock, 0, 1 ) ){}
        __sync_synchronize();

	// Cache_index points to next free slot
	cache[ *cache_index ] = match;
	*cache_index = (*cache_index) + 1;
	if( *cache_index >= cache_count ) *cache_index = 0;

	// Unlock mutex
        __sync_synchronize();
        _cache_lock = 0;
}



void analytics_posture_contribution( ASCTI_Item_t *item )
{
	int hooked = 0, record;
	CHECK_HOOK(TCL_Random, hooked, record);
	CHECK_HOOK(message_add, hooked, record);
	CHECK_HOOK(MPROTECT_NOM, hooked, record);
	CHECK_HOOK(guarded_uint32_set, hooked, record);
	CHECK_HOOK(analytics_posture_contribution, hooked, record);
	CHECK_HOOK(analytics_get_posture, hooked, record);
	CHECK_HOOK(analytics_platform, hooked, record);
	REPORT_HOOKING(hooked, record);

	analytics_platform( item );

	// Special re-entry fix:
	if( item->test == CTI_TEST_ELEVATEDMONITORING ) return;

	uint32_t flags = 0, orig_flags;
	// NOTE: guarded_uint32_get reports integrity internally
	int res = guarded_uint32_get(GUARDED_SLOT_POSTURE, &flags);
	orig_flags = flags;
	if( res == 0 && flags == 0 ) flags = A_FLAG_ALWAYS;

	// update flags accordingly
	if( item->test == CTI_TEST_INITIALIZATIONCOMPLETE ) flags |= A_FLAG_COMPLETED;

	if( item->test == CTI_TEST_KNOWNMALWAREARTIFACTDETECTED ||
		item->test == CTI_TEST_PUBLICSTOLENCERTSIGNERPRESENT ||
		item->test == CTI_TEST_EXPECTEDSIGNERFAILURE ||
		item->test == CTI_TEST_KNOWNMALWARESIGNERPRESENT ) flags |= A_FLAG_MALWARE;

	if( item->test == CTI_TEST_SYNTHETICSYSTEMARTIFACT ) flags |= A_FLAG_EMULATOR;

	if( item->test == CTI_TEST_NONPRODUCTIONSYSTEMARTIFACT ||
		item->test == CTI_TEST_SYSTEMUNSIGNED ) flags |= A_FLAG_NONPROD;

	if( item->test == CTI_TEST_DEVELOPMENTARTIFACT ||
		item->test == CTI_TEST_ADBDRUNNING ||
		item->test == CTI_TEST_TESTAUTOMATIONTOOLINSTALLED ) flags |= A_FLAG_DEVTOOL;

	if( item->test == CTI_TEST_PRIVILEGEPROVIDINGAPPLICATIONINSTALLED ||
		item->test == CTI_TEST_SYSTEMROOTJAILBREAK ||
		item->test == CTI_TEST_SECURITYHIDINGTOOLINSTALLED ) flags |= A_FLAG_ROOTED;

	if( item->test == CTI_TEST_HACKINGTOOLINSTALLED ||
		item->test == CTI_TEST_APPLICATIONTAMPERINGTOOLINSTALLED ||
		item->test == CTI_TEST_SECURITYSUBVERSIONTOOLINSTALLED ) flags |= A_FLAG_HACKTOOL;

	if( item->test == CTI_TEST_GAMECHEATTOOLINSTALLED ||
		item->test == CTI_TEST_APPPURCHASINGFRAUDTOOLINSTALLED ) flags |= A_FLAG_GAMETOOL;

	if( item->test == CTI_TEST_SECURITYEXPECTATIONFAILURE ||
		item->test == CTI_TEST_SECURITYOPERATIONFAILED ) flags |= A_FLAG_SEFSOF;

	if( item->test == CTI_TEST_DEBUGINSTRUMENTATIONARTIFACT ) flags |= A_FLAG_DEBUGGER;

	if( item->test == CTI_TEST_APPLICATIONTAMPERINGDETECTED ||
		item->test == CTI_TEST_INTERNALHOOKINGDETECTED ||
		item->test == CTI_TEST_STEALTHCALLBACKFAILURE ||
		item->test == CTI_TEST_HEARTBEATFAILURE
#ifdef __APPLE__
		|| item->test == CTI_TEST_PROVISIONINGMISSING
		|| item->test == CTI_TEST_PROVISIONINGCORRUPTED
#endif
		) flags |= A_FLAG_TAMPERING;

	if( item->test == CTI_TEST_SSLPINVIOLATION ||
		item->test == CTI_TEST_MITMDETECTED ) flags |= A_FLAG_NETWORK;

	if( item->test == CTI_TEST_APPLICATIONUNSIGNED
		|| item->test == CTI_TEST_DEBUGBUILD
		|| item->test == CTI_TEST_APPLICATIONUNENCRYPTED
		|| item->test == CTI_TEST_APPLICATIONDEVELOPERSIGNED
#ifdef __APPLE__
		|| item->test == CTI_TEST_APPLICATIONENCRYPTIONDISABLED
#endif
		) flags |= A_FLAG_DEVBUILD;

	if( res == 0 && flags != orig_flags ) guarded_uint32_set(GUARDED_SLOT_POSTURE, flags);

	// Check for flags issues that are signs of tampering
	// NOTE: this has to be done outside the mutex lock, since message_add()
	// can recurse back here
	if( res > 0 || (flags & A_FLAG_ALWAYS) == 0 || (flags & A_FLAG_NEVER) ){
		ALOG("CI:ERR: analytics FLAG_ALWAYS/FLAG_NEVER tripped");
		ASCTI_Item_t item;
		MEMSET( &item, 0, sizeof(item));
		item.test = CTI_TEST_APPLICATIONTAMPERINGDETECTED;
		item.subtest = _SUBTEST_INTERNAL_INTEGRITY;
		item.data3_type = ASCTI_DT_VRID;
		item.data3 = ERRORBASE+__LINE__;
		message_add( &item );

		flags |= A_FLAG_TAMPERING;
	}

	// Mark elevated risk (NOTE: once elevated, it doesn't decrease)
	if( (flags & (A_FLAG_MALWARE|A_FLAG_EMULATOR|A_FLAG_NONPROD|A_FLAG_ROOTED
			|A_FLAG_HACKTOOL|A_FLAG_DEBUGGER|A_FLAG_TAMPERING
			|A_FLAG_SEFSOF|A_FLAG_GAMETOOL|A_FLAG_DEVTOOL) ) > 0 ){
        	while( !__sync_bool_compare_and_swap( &_cache_lock, 0, 1 ) ){}
        	__sync_synchronize();

		if( _CONFIG.flag_elevated_monitoring == 0 ){
			// Inform that we are entering elevated monitoring
			ALOG("CI:TAG: Entering elevated monitoring mode");
			ASCTI_Item_t item;
			MEMSET( &item, 0, sizeof(item));
			item.test = CTI_TEST_ELEVATEDMONITORING;
			item.data3_type = ASCTI_DT_NUMBER;
			item.data3 = flags;
			message_add( &item );
		}
		_CONFIG.flag_elevated_monitoring = 1;

		if( (flags & (A_FLAG_DEBUGGER|A_FLAG_TAMPERING)) > 0 ){
			if( guarded_uint32_set(GUARDED_SLOT_MONLEVEL, flags) > 0 ){
				// NOTE: only happens if there is an MPROTECT failure; guarded_set
				// already sent error_report.  It's not exactly tampering (confirmed),
				// so nothing to do...
			}
		} else {
			if( guarded_uint32_set(GUARDED_SLOT_MONLEVEL, 1) > 0 ){
				// NOTE: only happens if there is an MPROTECT failure; guarded_set
				// already sent error_report.  It's not exactly tampering (confirmed),
				// so nothing to do...
			}
		}

		__sync_synchronize();
     		_cache_lock = 0;
	}
}


uint32_t analytics_get_posture(){

	int hooked = 0, record;
	CHECK_HOOK(TCL_Random, hooked, record);
	CHECK_HOOK(message_add, hooked, record);
	CHECK_HOOK(MPROTECT_NOM, hooked, record);
	CHECK_HOOK(guarded_uint32_get, hooked, record);
	CHECK_HOOK(analytics_posture_contribution, hooked, record);
	CHECK_HOOK(analytics_get_posture, hooked, record);
	REPORT_HOOKING(hooked, record);

	uint32_t flags = 0;
	int res = guarded_uint32_get(GUARDED_SLOT_POSTURE, &flags);

	flags = flags & 0x0fffffff;
	// NOT-MVP-TODO: calculate a trust/posture score in top 4 bits
	// flags |= (score) << 28;

	// Check for flags issues that are signs of tampering
	if( res > 0 || (flags & A_FLAG_ALWAYS) == 0 || (flags & A_FLAG_NEVER) ){
		ALOG("CI:ERR: analytics FLAG_ALWAYS/FLAG_NEVER tripped");
		ASCTI_Item_t item;
		MEMSET( &item, 0, sizeof(item));
		item.test = CTI_TEST_APPLICATIONTAMPERINGDETECTED;
		item.subtest = _SUBTEST_INTERNAL_INTEGRITY;
		item.data3_type = ASCTI_DT_VRID;
		item.data3 = ERRORBASE+__LINE__;
		message_add( &item );
	}

	return flags;
}
