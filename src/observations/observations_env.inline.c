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

#ifndef _OB_ENV_INLINE_C_
#define _OB_ENV_INLINE_C_

#define ERRORBASE_OBE 36000

#include "observations_item_common.inline.c"

#define FLAGS_FILTER	0xFFFF04FF

#define WORK_MAX_OBE 8

static const uint32_t LD_PRELOAD[] = {0x2f291a0,0x16cf27ac,0x418f9cb0,}; // "LD_PRELOAD="
static const uint32_t LD_LIBRARY_PATH[] = {0x1ef291a0,0x4d120b7,0x3f386b8,0x6dc229a5,0x22a7cefe,}; // "LD_LIBRARY_PATH="
static const uint32_t CLASSPATH[] = {0x1ec99af,0xedc3aa2,0x59a1f8b7,}; // "CLASSPATH="
static const uint32_t BOOTCLASSPATH[] = {0x6e29aae,0xed225b3,0xdee8abd,0x5e974ca9,}; // "BOOTCLASSPATH="
static const uint32_t DYLD_INSERT_LIBRARIES[] = {0x16e18ca8,0x1ede36a9,0x16f79bb1,0x17cc29a1,0x1de09cbb,0x56817fb2,}; // "DYLD_INSERT_LIBRARIES"
static const uint32_t DYLD_[] = {0x16e18ca8,0x4d907fa9,}; // "DYLD_"

#define _S_OBE(nom) _decode((sizeof(nom)/4)-1,nom,work)

extern char **environ;

__attribute__((always_inline))
static inline void observations_env()
{
	ASCTI_Item_t item;
	uint32_t work[WORK_MAX_OBE];

#define CACHE_SIZE 32
        uint64_t cache[CACHE_SIZE];
        MEMSET(cache, 0, sizeof(cache));
        uint8_t cache_index = 0;

	// Walk the environment
	int i = 0;
	while( environ[i] != NULL ){

		// Identify special targest
		int end=0, is_cp=0, is_ldp=0, is_ldlp=0;

#if SYSTEMID == 2
		// Android
		if( MEMCMP(environ[i], _S_OBE(LD_PRELOAD), 11) == 0 ) is_ldp++;
		else if( MEMCMP(environ[i], _S_OBE(LD_LIBRARY_PATH), 16) == 0 ) is_ldlp++;
		else if( MEMCMP(environ[i], _S_OBE(CLASSPATH), 10) == 0 || MEMCMP(environ[i], _S_OBE(BOOTCLASSPATH), 14) == 0 ) is_cp++;
#endif

#if SYSTEMID == 1
		// IOS

		// NOTE: things like substrate use DYLD_ flags, but there is no debugger; so it's
		// a little messy here in classifying what is what, but overall when there is
		// anything DYLD_, it's typically a bad sign of some sort.

		if( MEMCMP(environ[i], _S_OBE(DYLD_INSERT_LIBRARIES), 21) == 0 ) is_ldp++;
		else if( MEMCMP(environ[i], _S_OBE(DYLD_), 5) == 0 ){
			ALOG("CI:TAG: DYLDENV found %s", environ[i]);
			ctiitem_setup_app( &item );
			item.test = CTI_TEST_DEBUGINSTRUMENTATIONARTIFACT;
			item.subtest = 41;
			item.data1_type = ASCTI_DT_ENV;
			item.data1 = environ[i];
			item.data1_len = STRLEN(environ[i]);
			message_add( &item );
		}
#endif

		// find the name end
		while( environ[i][end] != '=' && environ[i][end] != 0 ) end++;

        	// Run through our strings

        	uint16_t id=0;
        	uint32_t resume=0, flags=0;
        	uint8_t buffer[ 256 ];

        	int res = TFDefs_String_Lookup( &_CONFIG.defs_as, ASDEFS_SECTION_ENV, buffer,
                	(uint16_t)sizeof(buffer), &resume, &flags, &id);
        	if( res != TFDEFS_FOUND ){
               		ALOG("CI:ERR: asdefs not found in env walk");
                	error_report( ERRORBASE_OBE+__LINE__, res, 0 );
                	return;
        	}
        	uint16_t reqlen = (buffer[1] << 8) + buffer[0];
        	ASSERT(reqlen < sizeof(buffer));

		while( 1 ){
        		res = TFDefs_String_Lookup( &_CONFIG.defs_as, ASDEFS_SECTION_ENV, buffer,
                		(uint16_t)sizeof(buffer), &resume, &flags, &id);
			if( res != TFDEFS_FOUND ) break;

			if( _CONFIG.flag_analytics_coalesce > 0 &&
                        	analytics_coalesce_check( cache, CACHE_SIZE, (flags & FLAGS_FILTER), id ) == 1 ){
                        	ALOG("COALESE on %d/%d", (flags & FLAGS_FILTER), id);
                        	continue;
                	}	

			if( flags & ASDEFS_FLAGS_ENVEXIST ){
				// match the name (only)
				size_t s = STRLEN((char*)buffer);
				if( s == end && MEMCMP(environ[i], buffer, s) == 0 ){
					// We found a match
					ALOG("CI:TAG: found ENVEXIST %s", environ[i]);
					ctiitem_setup_app( &item );
					item.subtest = id;
					item.data1_type = ASCTI_DT_ENV;
					item.data1 = environ[i];
					item.data1_len = STRLEN(environ[i]);

					observations_item_common( ASDEFS_SECTION_ENV, &item, (flags & FLAGS_FILTER) );

                                	if( _CONFIG.flag_analytics_coalesce > 0 ){
                                       		ALOG("ADDCOALESE on %d/%d", (flags & FLAGS_FILTER), id);
                                        	analytics_coalesce_add( cache, CACHE_SIZE,
                                                	&cache_index, (flags & FLAGS_FILTER), id );
                                	}
				}
			}

#if SYSTEMID == 2
			// Android
			// If this string wants bootclass, and this isn't bootclass, skip
			if( (flags & ASDEFS_FLAGS_BOOTCLASS) && is_cp == 0 ) continue;

			// If this string wants ldlibpath, and this isn't ldlibpath, skip
			if( (flags & ASDEFS_FLAGS_LDLIBPATH) && is_ldlp == 0 ) continue;

			// If this string wants ldpreload, and this isn't ldpreload, skip
			if( (flags & ASDEFS_FLAGS_LDPRELOAD) && is_ldp == 0 ) continue;
#endif

#if SYSTEMID == 1
			// IOS

			// If this string wants ldpreload, and this isn't ldpreload, skip
			if( (flags & ASDEFS_FLAGS_DYLDLIB) && is_ldp == 0 ) continue;
#endif

			// If we get here, we got one of the specific var strings, which
			// means search the value

			if( STRSTR( &environ[i][end], (char*)buffer ) != NULL ){
				// We found the needle in the haystack
				ALOG("CI:TAG: found ENV strstr %s", environ[i]);
				ctiitem_setup_app( &item );
				item.subtest = id;
				item.data1_type = ASCTI_DT_ENV;
				item.data1 = environ[i];
				item.data1_len = STRLEN(environ[i]);

				observations_item_common( ASDEFS_SECTION_ENV, &item, flags );

                               	if( _CONFIG.flag_analytics_coalesce > 0 ){
                                     	ALOG("ADDCOALESE on %d/%d", flags, id);
                                       	analytics_coalesce_add( cache, CACHE_SIZE,
                                               	&cache_index, (flags & FLAGS_FILTER), id );
                               	}
			}
		}

		i++;
	}
}

#endif
