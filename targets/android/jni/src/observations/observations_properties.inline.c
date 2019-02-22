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

#ifndef _OB_PROPERTIES_INLINE_C_
#define _OB_PROPERTIES_INLINE_C_

#define ERRORBASE_PROP	21000

#include "observations_item_common.inline.c"

#define FLAGS_FILTER_P	0xFFFE07FF

__attribute__((always_inline))
static inline void observations_properties()
{
	char prop_value[PROP_VALUE_MAX];
	ASCTI_Item_t item;
	ctiitem_setup_sys( &item );

	ALOG("CI:TAG: Props starting");

#define CACHE_SIZE 32
        uint64_t cache[CACHE_SIZE];
        MEMSET(cache, 0, sizeof(cache));
        uint8_t cache_index = 0;

	uint16_t id=0;
	uint32_t resume=0, flags=0;
	uint8_t buffer[128], buffer2[128];
	ASSERT( sizeof(buffer) == sizeof(buffer2) );

	// Perform the initial lookup, to get the buffer sizes
	int res = TFDefs_String_Lookup( &_CONFIG.defs_as, ASDEFS_SECTION_PROPS, buffer,
		(uint16_t)sizeof(buffer), &resume, &flags, &id );
	if( res != TFDEFS_FOUND ){
		ALOG("CI:ERR: asdefs props not found");
		error_report( ERRORBASE_PROP+__LINE__, res, 0 );
		return;
	}

	uint16_t reqlen = (buffer[1] << 8) + buffer[0];
	ASSERT(reqlen < sizeof(buffer));
	ASSERT(reqlen < sizeof(buffer2));

	int prop_value_len = 0, skip_contains_children = 0;

	//
	// NOTE: *technically* the code below allows an undefined state behavior
	// of processing PROPCONTAINSCHILD without a preceeding PROPCONTAINS.  That is
	// actually a data formatting issue (pre-compile-time).  We are not going to
	// include runtime logic to detect dev-time/compile-time errors, sane defs file
	// contents have to be verified before shipping, not after.  Thus, the code
	// below will not catch orphan PROPCONTAINSCHILD.
	//

	while(1){
		// Get the next string
		res = TFDefs_String_Lookup( &_CONFIG.defs_as, ASDEFS_SECTION_PROPS, buffer,
			(uint16_t)sizeof(buffer), &resume, &flags, &id );
		if( res != TFDEFS_FOUND ){ break; }

		// Skip any contains children, if warranted
		if( skip_contains_children && (flags & ASDEFS_FLAGS_PROPCONTAINSCHILD) ){ continue; }

		// Skip this string if we've flagged it already.
		// NOTE: a PROPSCONTAINS initial property string will have flags=0, which will never
		// be cached.  Each follow-on contains children have individual IDs, which may be
		// skipped here.
		if( _CONFIG.flag_analytics_coalesce > 0 &&
			analytics_coalesce_check( cache, CACHE_SIZE, (flags & FLAGS_FILTER_P), id ) == 1 ){
				ALOG("COALESE on %d/%d", (flags & FLAGS_FILTER_P), id);
				continue;
		}

		// Process the string, depending on whether it's a PROPCONTAINSCHILD or not
		if( (flags & ASDEFS_FLAGS_PROPCONTAINSCHILD) == 0 ){

			// It's a property lookup string (not a contains child)

			prop_value_len = property_get((char*)buffer, prop_value);
			if( prop_value_len <= 0 ){
				// Doesn't exist; HOWEVER if it's PROPCONTAINS, we need to
				// loop past all the contains strings too
				if( flags & ASDEFS_FLAGS_PROPCONTAINS ){
					ALOG("CI:TAG: skipping children for prop '%s'", buffer);
					skip_contains_children++;
				}
				continue;
			}

			// It exists

			// If it's PROPCONTAINS, do special handling
			if( flags & ASDEFS_FLAGS_PROPCONTAINS ){
				// Rest our skip flag
				skip_contains_children = 0;

				// We have to save the property name, because it's
				// going to be overridden in next loop
				TFMEMCPY( buffer2, buffer, sizeof(buffer) );

				// PROPCONTAINS has no more processing, so go on to next string
				continue;
			}

			// It's not a PROPCONTAINS or PROPCONTAINSCHILD, so fall thru to
			// match processing
		}
		else
		{
			// It's a CONTAINSCHILD, attempt the search

			if( STRSTR(prop_value, (char*)buffer) == NULL ){
				// Not found, so go on to next string
				continue;
			}

			// If we get here, we found the needle in the haystack; report the match
			// We have to move the saved property name (in buffer2) back to buffer,
			// so it's reported correctly
			TFMEMCPY( buffer, buffer2, sizeof(buffer) );
			goto match;
		}

		// Property exists, now check our match criteria

		if( flags & ASDEFS_FLAGS_PROPEXIST ){ goto match; }
		else if( (flags & ASDEFS_FLAGS_PROPVALNOT1) && prop_value[0] != '1' ){ goto match; }
		else if( (flags & ASDEFS_FLAGS_PROPVALNOT0) && prop_value[0] != '0' ){ goto match; }

		// if we get here, there is no match, so just loop
		continue;

match:
		// Something matched, so report it

		item.subtest = id;
		item.data1 = buffer;
		item.data1_len = STRLEN((char*)buffer);
		item.data1_type = ASCTI_DT_PROPERTYNAME;

		item.data2 = prop_value;
		item.data2_len = prop_value_len;
		item.data2_type = ASCTI_DT_STRING;

		// If we get here, something matched; send the CTI
		observations_item_common( ASDEFS_SECTION_PROPS, &item, (flags & FLAGS_FILTER_P) );

		// SPECIAL: if this is cyanogenmod, mark it so
		if( id == _SUBTEST_NP_CM ) _PLATFORM_CONFIG.is_cyanogenmod = 1;

		if( _CONFIG.flag_analytics_coalesce > 0 ){
			ALOG("ADDCOALESE on %d/%d", (flags & FLAGS_FILTER_P), id);
			analytics_coalesce_add( cache, CACHE_SIZE, &cache_index, (flags & FLAGS_FILTER_P), id );
		}
	}

	ALOG("CI:TAG: Props finishing");
}

#endif
