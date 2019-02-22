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

#ifndef _OB_FILES_INLINE_C_
#define _OB_FILES_INLINE_C_

#include <errno.h>

#include "as_ma_private.h"
#include "as_defs_flags.h"
#include "ascti_tests.h"

#include "tf_defs.h"

#include "config.h"

#define ERRORBASE_OF	35000

#include "observations_item_common.inline.c"

__attribute__((always_inline))
static inline int observations_files(uint8_t section){

	uint16_t id=0;
	uint32_t resume=0, flags=0;
	uint8_t buffer[ 512 ];

	// Do the initial lookup to get size, etc.
	int res = TFDefs_String_Lookup( &_CONFIG.defs_as, section,
		buffer, (uint16_t)sizeof(buffer), &resume, &flags, &id);
	if( res != TFDEFS_FOUND ){
		ALOG("CI:ERR: failed asdefs.files init lookup");
		return error_report(ERRORBASE_OF+__LINE__,res,-1);
	}
	uint16_t reqlen = (buffer[1] << 8) + buffer[0];
	ASSERT(reqlen < sizeof(buffer) );

	// SPECIAL: the first string is a base directory
	res = TFDefs_String_Lookup( &_CONFIG.defs_as, section,
		buffer, (uint16_t)sizeof(buffer), &resume, &flags, &id);
	if( res != TFDEFS_FOUND ){
		ALOG("CI:ERR: failed asdefs.files basedir lookup");
		return error_report(ERRORBASE_OF+__LINE__,res,-1);
	}
	ALOG("CI:TAG: F-BASEPATH: %s", buffer);

	int basefd = AT_FDCWD;
	// NOTE: We don't use a base path on IOS, so we just fall thru with AT_FDCWD
	// even tho basefd is essentially never used
#ifndef __APPLE__
	do {
		basefd = OPEN((char*)buffer, O_RDONLY|O_DIRECTORY|O_NOFOLLOW, 0);
	} while( basefd == -1 && errno == EINTR );
	if( basefd == -1 ){
		ALOG("CI:ERR: failed asdefs.files basedir open");
		return error_report(ERRORBASE_OF+__LINE__,errno,-1);
	}
#else
	// Apple: just make it cwd
	ASSERT( basefd == AT_FDCWD );
#endif

	// Set up a common ASCTI item
	ASCTI_Item_t item;
	ctiitem_setup_app( &item );
	item.data1_type = ASCTI_DT_FILE;

#define CACHE_SIZE 32
	uint64_t cache[CACHE_SIZE];
	MEMSET(cache, 0, sizeof(cache));
	uint8_t cache_index = 0;

	// Now walk the strings
	while(1){
		res = TFDefs_String_Lookup( &_CONFIG.defs_as, section,
			buffer, (uint16_t)sizeof(buffer), &resume, &flags, &id);
		if( res != TFDEFS_FOUND ) break;
		//ALOG("- FILECHECK: %s", buffer);

		if( _CONFIG.flag_analytics_coalesce > 0 &&
			analytics_coalesce_check( cache, CACHE_SIZE, flags, id ) == 1 ){
			ALOG("CI:TAG: COALESE on %d/%d", flags, id);
			continue;
		}

		// NOTE: no EINTR for this:
#ifdef __APPLE__
		// NOTE: early IOS doesn't have faccessat(), so we just use access()
		res = ACCESS((char*)buffer, F_OK);
#else
		res = FACCESSAT(basefd, (char*)buffer, F_OK, 0);
#endif
		if( res == 0 ){
			// File exists...
			ALOG("CI:TAG: - FOUND: %s", buffer);
			item.subtest = id;
			// NOTE: the file path here lacks /system/
			item.data1 = (char*)buffer;
			item.data1_len = (uint16_t)STRLEN((char*)buffer);
			observations_item_common( section, &item, flags );

			if( _CONFIG.flag_analytics_coalesce > 0 ){
				ALOG("CI:TAG: ADDCOALESE on %d/%d", flags, id);
				analytics_coalesce_add( cache, CACHE_SIZE, 
					&cache_index, flags, id );
			}
		}
	}

	// clean up our base fd
	if( basefd != AT_FDCWD) CLOSE(basefd);
	return 0;
}

#endif
