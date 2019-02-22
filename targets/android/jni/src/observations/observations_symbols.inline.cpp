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

#ifndef _OB_SYMBOLS_INLINE_C_
#define _OB_SYMBOLS_INLINE_C_

#include <jni.h>
#include <dlfcn.h>

#include "tf_defs.h"

#include "as_ma_private.h"
#include "as_defs_flags.h"
#include "ascti_tests.h"

#include "config.h"

#define ERRORBASE_OBS 22000

#include "observations_item_common.inline.c"

#define FLAGS_FILTER_S	0xffff0fff

__attribute__((always_inline))
static inline int observations_symbols(JNIEnv *env)
{
	ASSERT(env);
	ALOG("CI:TAG: Symbols start");

	uint16_t id=0;
	uint32_t resume=0, flags=0;
	uint8_t buffer[ 256 ];

	// Do the initial lookup to get size, etc.
	int res = TFDefs_String_Lookup( &_CONFIG.defs_as, ASDEFS_SECTION_SYMBOLS,
		buffer, (uint16_t)sizeof(buffer), &resume, &flags, &id);
	if( res != TFDEFS_FOUND ){
		ALOG("ERR failed asdefs.syms init lookup");
		// NOT-MVP-TODO: is this an internal integrity error?
		return error_report(ERRORBASE_OBS+__LINE__, res, -1);
	}
	uint16_t reqlen = (buffer[1] << 8) + buffer[0];
	ASSERT(reqlen < sizeof(buffer) );

	// Set up a common ASCTI item
	ASCTI_Item_t item;
	ctiitem_setup_app( &item );
	MEMSET( &item, 0, sizeof(item) );
	item.data1_type = ASCTI_DT_SYMBOL;
	item.data1 = buffer;

#define CACHE_SIZE 32
        uint64_t cache[CACHE_SIZE];
        MEMSET(cache, 0, sizeof(cache));
        uint8_t cache_index = 0;

	// Now walk the strings
	while(1){
		res = TFDefs_String_Lookup( &_CONFIG.defs_as, ASDEFS_SECTION_SYMBOLS,
			buffer, (uint16_t)sizeof(buffer), &resume, &flags, &id);
		if( res != TFDEFS_FOUND ) break;
		//ALOG("- SYMCHECK: %s", buffer);

                if( _CONFIG.flag_analytics_coalesce > 0 &&
                        analytics_coalesce_check( cache, CACHE_SIZE, (flags & FLAGS_FILTER_S), id ) == 1 ){
                        ALOG("COALESE on %d/%d", (flags & FLAGS_FILTER_S), id);
                        continue;
                }

		if( flags & ASDEFS_FLAGS_SYMJAVACLASS ){
			jclass needle = env->FindClass( (char*)buffer );
			if( !env->ExceptionCheck() && needle != NULL ){
				ALOG("- SYM found: %s", buffer);
				item.data1_len = STRLEN((char*)buffer);
				observations_item_common( ASDEFS_SECTION_SYMBOLS, &item, (flags & FLAGS_FILTER_S) );

                        	if( _CONFIG.flag_analytics_coalesce > 0 ){
                                	ALOG("ADDCOALESE on %d/%d", (flags & FLAGS_FILTER_S), id);
                                	analytics_coalesce_add( cache, CACHE_SIZE, &cache_index, 
						(flags & FLAGS_FILTER_S), id );
                        	}
			}
			env->ExceptionClear();
			if( needle != NULL ) env->DeleteLocalRef(needle);
		}
		if( (flags & ASDEFS_FLAGS_SYMNATIVE) 
#ifdef __i386__
				&& (_PLATFORM_CONFIG.api != 19) 
#endif
){
			// BIG HUGE HAIRY PROBLEM: Android API 19 on x86can crash when trying to dlsym
			// an unknown symbol.  This is a known bug.  We don't have a work-around for
			// for this right now, so we just have to disable native symbol lookup
			// on API 19 (KitKat).  Which is a huge loss.  :/
			// https://code.google.com/p/android/issues/detail?id=61799
			// NOT-MVP-TODO: what to do here
	
			void *c = dlsym( RTLD_DEFAULT, (char*)buffer );
			if( c != NULL ){
				ALOG("- SYM found: %s", buffer);
				item.data1_len = STRLEN((char*)buffer);
				observations_item_common( ASDEFS_SECTION_SYMBOLS, &item, (flags & FLAGS_FILTER_S) );

                        	if( _CONFIG.flag_analytics_coalesce > 0 ){
                                	ALOG("ADDCOALESE on %d/%d", (flags & FLAGS_FILTER_S), id);
                                	analytics_coalesce_add( cache, CACHE_SIZE, &cache_index, 
						(flags & FLAGS_FILTER_S), id );
                        	}
			}
		}
	}

	ALOG("CI:TAG: Symbols finish");
	return 0;
}

#endif
