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

#include <CoreFoundation/CoreFoundation.h>
#include <objc/runtime.h>
#include <objc/message.h>

#include <dlfcn.h>

#include "tf_defs.h"

#include "as_ma_private.h"
#include "as_defs_flags.h"
#include "ascti_tests.h"

#include "config.h"

#define ERRORBASE_OBS 54000

#include "observations_item_common.inline.c"

__attribute__((always_inline))
static inline int observations_symbols(uint8_t section){

	uint32_t flags=0;
	uint16_t id=0;
	uint32_t resume = 0;
	uint8_t buffer[ 256 ];

	// Do the initial lookup to get size, etc.
	int res = TFDefs_String_Lookup( &_CONFIG.defs_as, section,
		buffer, (uint16_t)sizeof(buffer), &resume, &flags, &id);
	if( res != TFDEFS_FOUND ){
		ALOG("CI:ERR: failed asdefs.files init lookup");
		// NOT-MVP-TODO: is this an internal integrity error?
		return error_report(ERRORBASE_OBS+__LINE__, res, -1);
	}
	uint16_t reqlen = (buffer[1] << 8) + buffer[0];
	ASSERT(reqlen < sizeof(buffer) );

	// Set up a common ASCTI item
	ASCTI_Item_t item;
	ctiitem_setup_app( &item );
	item.data1_type = ASCTI_DT_SYMBOL;
	item.data1 = buffer;

#define CACHE_SIZE 32
        uint64_t cache[CACHE_SIZE];
        MEMSET(cache, 0, sizeof(cache));
        uint8_t cache_index = 0;

	// Now walk the strings
	while(1){
		res = TFDefs_String_Lookup( &_CONFIG.defs_as, section,
			buffer, (uint16_t)sizeof(buffer), &resume, &flags, &id);
		if( res != TFDEFS_FOUND ) break;
		//ALOG("- SYMCHECK: %s", buffer);

                if( _CONFIG.flag_analytics_coalesce > 0 &&
                        analytics_coalesce_check( cache, CACHE_SIZE, flags, id ) == 1 ){
                        ALOG("CI:TAG: COALESE on %d/%d", flags, id);
                        continue;
                }

		if( flags & ASDEFS_FLAGS_SYM_OBJC_CLASS ){
			Class cl = objc_getClass((char*)buffer);
			if( cl != NULL ){
				ALOG("CI:TAG: - CLASS found: %s", buffer);
				item.data1_len = STRLEN((char*)buffer);
				observations_item_common( section, &item, flags );

                        	if( _CONFIG.flag_analytics_coalesce > 0 ){
                                	ALOG("CI:TAG: ADDCOALESE on %d/%d", flags, id);
                                	analytics_coalesce_add( cache, CACHE_SIZE,
                                        	&cache_index, flags, id );
                        	}
			}
		}
		if( flags & ASDEFS_FLAGS_SYM_NATIVE ){
			void *c = dlsym( RTLD_DEFAULT, (char*)buffer );
			if( c != NULL ){
				ALOG("CI:TAG: - SYM found: %s", buffer);
				item.data1_len = STRLEN((char*)buffer);
				observations_item_common( section, &item, flags );

                        	if( _CONFIG.flag_analytics_coalesce > 0 ){
                                	ALOG("CI:TAG: ADDCOALESE on %d/%d", flags, id);
                                	analytics_coalesce_add( cache, CACHE_SIZE,
                                        	&cache_index, flags, id );
                        	}
			}
		}
	}

	return 0;
}

#endif
