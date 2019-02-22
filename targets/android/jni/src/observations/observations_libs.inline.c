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

#ifndef _OB_LIBS_INLINE_C_
#define _OB_LIBS_INLINE_C_

#include <dlfcn.h>
#include <errno.h>

#include "tf_cal.h"
#include "tf_linux.h"
#include PLATFORM_H

#include "observations_item_common.inline.c"

#define ERRORBASE_L 15000

#define CACHE_SIZE 32
struct _libs_callback_state {
	uint64_t	cache[CACHE_SIZE];
	uint8_t 	cache_index;
	uint8_t		self_found;
	void 		*self_base;
	void		*libc_base;
	uint8_t 	last_nom[512];
	size_t 		last_nom_sz;
	uint32_t	flag_repeat : 1;
	uint32_t	count_libc : 28;
};


static void libs_callback( void *state, void *s, void *e, char *perm, char *nom )
{
	struct _libs_callback_state *st = (struct _libs_callback_state*)state;
	if( perm == NULL || nom == NULL ){
		// All done
		return;
	}

	if( nom[0] == 0 ) return; // anonymous mem, not much we can do with it

	size_t nom_sz = STRLEN(nom);
	if( nom_sz > sizeof(st->last_nom) ) nom_sz = sizeof(st->last_nom);
	// NOTE: we exempt ourselves, we want to see all our sections
	if( nom_sz == st->last_nom_sz ){
		if( MEMCMP(nom, st->last_nom, nom_sz) == 0 ){
			// We've seen this name already

			if( perm[2] == 'x' ){
				// it's an executable section

				// SPECIAL: we do keep track how many libc's we see,
				// and note if any are rwx.  mmap pages over libc will
				// make discontiguous maps for libc, and rwx means it
				// was left mprotect open.  Both are general heuristics
				// of libc hooking.

				if( nom[ nom_sz-4] == 'c' && nom[ nom_sz-5] == 'b' &&
					nom[nom_sz-5] =='i' && nom[nom_sz-6]=='l' &&
					nom[nom_sz-7] == '/' )
				{
					ALOG("CI:TAG: libc found");
					st->count_libc++;

					// TODO: subject this to cache?
					if( perm[1] == 'w' ){
						// writable libc section found
						ALOG("CI:TAG: libc section writable");
						ASCTI_Item_t item;
						ctiitem_setup_app( &item );
						item.test = CTI_TEST_APPLICATIONTAMPERINGDETECTED;
						item.subtest = 115;
						message_add( &item );
					}
				}
			}
			return;
		}
	}
	st->last_nom_sz = nom_sz;
	MEMCPY( st->last_nom, nom, nom_sz );

	//ALOG("CI:LIB: '%s'", nom);

	// Run through our strings
	uint16_t id=0;
	uint32_t resume=0, flags=0;
	uint8_t buffer[ 256 ];

	int res = TFDefs_String_Lookup( &_CONFIG.defs_as, ASDEFS_SECTION_LIBS, buffer,
		(uint16_t)sizeof(buffer), &resume, &flags, &id);
	if( res != TFDEFS_FOUND ){
		ALOG("CI:ERR: asdefs not found in maps walk");
		error_report( ERRORBASE_L+__LINE__, res, 0 );
		return;
	}
	uint16_t reqlen = (buffer[1] << 8) + buffer[0];
	ASSERT(reqlen < sizeof(buffer));

	while( 1 ){
		res = TFDefs_String_Lookup( &_CONFIG.defs_as, ASDEFS_SECTION_LIBS, buffer,
			(uint16_t)sizeof(buffer), &resume, &flags, &id);
		if( res != TFDEFS_FOUND ) break;

                if( _CONFIG.flag_analytics_coalesce > 0 &&
                        analytics_coalesce_check( st->cache, CACHE_SIZE, flags, id ) == 1 ){
                        //ALOG("CI:TAG: COALESE on %d/%d", flags, id);
                        continue;
                }

		if( STRSTR(nom, (char*)buffer) != NULL ){
			// We found a match
			ASCTI_Item_t item;
			ctiitem_setup_app( &item );
			item.subtest = id;
			item.data1_type = ASCTI_DT_LIBRARY;
			item.data1 = nom;
			item.data1_len = (uint16_t)STRLEN(nom);

			observations_item_common( ASDEFS_SECTION_LIBS, &item, flags );

                        if( _CONFIG.flag_analytics_coalesce > 0 ){
                                //ALOG("CI:TAG: ADDCOALESE on %d/%d", flags, id);
                                analytics_coalesce_add( st->cache, CACHE_SIZE,
                                        &st->cache_index, flags, id );
                        }
		}
	}

	// Is this us?
	if( st->flag_repeat == 0 && s == st->self_base ){
		ALOG("CI:TAG: Found self %p-%p %c (%s)", s, e, perm[2], nom);

		ASCTI_Item_t item;
		size_t psz = STRLEN(nom);
		if( psz >= sizeof(_PLATFORM_CONFIG.asmalib) - 1 ){
			error_report(ERRORBASE_L+__LINE__,psz,0);
		} else {
			MEMCPY( _PLATFORM_CONFIG.asmalib, nom, psz );
		}
		if( perm[2] != 'x' ){
			ALOG("CI:ERR: self base map not +x");
			error_report(ERRORBASE_L+__LINE__,0,0);
			ctiitem_setup_app( &item );
			item.test = CTI_TEST_SECURITYEXPECTATIONFAILURE;
			item.subtest = 103;
			item.data3_type = ASCTI_DT_VRID;
			item.data3 = ERRORBASE_L+__LINE__;
			message_add( &item );
			return;
		}

		_PLATFORM_CONFIG.code_start = s;
		_PLATFORM_CONFIG.code_len = (e - s);
	}
}


static int _first = 0;
static struct _libs_callback_state _st;

__attribute__((always_inline))
static inline void observations_libs()
{
	if( _first == 0 ){
		MEMSET( &_st, 0, sizeof(_st) );
		_first++;

		// Look up self
		Dl_info dli;
		if( dladdr( observations_libs, &dli ) == 0 ){
			ALOG("CI:ERR: Unable to dladdr self");
			error_report( ERRORBASE_L+__LINE__, 0, 0 );
			ASCTI_Item_t item;
			ctiitem_setup_app( &item );
			item.test = CTI_TEST_SECURITYOPERATIONFAILED;
			item.subtest = _SUBTEST_INTERNAL_INTEGRITY;
			item.data3 = ERRORBASE_L+__LINE__;
			item.data3_type = ASCTI_DT_VRID;
			message_add( &item );
			return;
		}
		_st.self_base = dli.dli_fbase;
	}

	ALOG("CI:TAG: Start maps walk");
	_st.count_libc = 0;
	int res = TFLinux_Maps_Walk( &_st, libs_callback );
	if( res != 0 ){
		ALOG("CI:ERR: LinuxMaps_walk res=%d errno=%d", res, errno);
		error_report( ERRORBASE_L+__LINE__, res, 0 );
		ASCTI_Item_t item;
		ctiitem_setup_app( &item );
		item.test = CTI_TEST_SECURITYOPERATIONFAILED;
		item.subtest = _SUBTEST_INTERNAL_INTEGRITY;
		item.data3 = ERRORBASE_L+__LINE__;
		item.data3_type = ASCTI_DT_VRID;
		message_add( &item );

	} else ALOG("CI:TAG: End maps walk");

	if( _st.flag_repeat == 0 ) _st.flag_repeat = 1;

	if( _st.count_libc > 1 &&
                ( _CONFIG.flag_analytics_coalesce == 0 ||
                analytics_coalesce_check( _st.cache, CACHE_SIZE, ASDEFS_FLAGS_ATD, 116 ) == 0) )
	{
		// We saw more than 1 libc executable section, which is a heuristic
		// for hooking.
		ALOG("CI:TAG: libc fractured");
		ASCTI_Item_t item;
		ctiitem_setup_app( &item );
		item.test = CTI_TEST_APPLICATIONTAMPERINGDETECTED;
		item.subtest = 116;
		message_add( &item );

		if( _CONFIG.flag_analytics_coalesce > 0 ){
			analytics_coalesce_add( _st.cache, CACHE_SIZE, &_st.cache_index, 
				ASDEFS_FLAGS_ATD, item.subtest );
		}
	}
}

#endif
