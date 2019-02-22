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

#ifndef _OB_ITEM_COMMON_INLINE_C_
#define _OB_ITEM_COMMON_INLINE_C_

#include "as_ma_private.h"
#include "ascti_tests.h"
#include "as_defs_flags.h"

__attribute__((always_inline))
static inline void observations_item_common( uint8_t section, ASCTI_Item_t *item, uint32_t flags )
{
	if( section == ASDEFS_SECTION_FILES ){
		//item->type = ASCTI_OBT_SYSTEM;
		// SPECIAL: if it's malware, adjust the type
		if( flags & ASDEFS_FLAGS_MAL ) item->type = ASCTI_OBT_MALWARE;
	}

	ALOG("CI:TAG: ITEMCOMMON sect=%d flags=%d", section, flags);

#define COUNT	12
	uint32_t X[][2] = {
		// Flag, test
		{ASDEFS_FLAGS_SS, CTI_TEST_SECURITYSUBVERSIONTOOLINSTALLED},
		{ASDEFS_FLAGS_SS2, CTI_TEST_SECURITYHIDINGTOOLINSTALLED},
		{ASDEFS_FLAGS_ATT, CTI_TEST_APPLICATIONTAMPERINGTOOLINSTALLED},
		{ASDEFS_FLAGS_ATD, CTI_TEST_APPLICATIONTAMPERINGDETECTED},
		{ASDEFS_FLAGS_DBG, CTI_TEST_DEBUGINSTRUMENTATIONARTIFACT},
		{ASDEFS_FLAGS_ROOT, CTI_TEST_SYSTEMROOTJAILBREAK},
		{ASDEFS_FLAGS_SEF, CTI_TEST_SECURITYEXPECTATIONFAILURE},
		{ASDEFS_FLAGS_HT, CTI_TEST_HACKINGTOOLINSTALLED},
		{ASDEFS_FLAGS_MAL, CTI_TEST_KNOWNMALWAREARTIFACTDETECTED},
		{ASDEFS_FLAGS_GCT, CTI_TEST_GAMECHEATTOOLINSTALLED},
		{ASDEFS_FLAGS_IAP, CTI_TEST_APPPURCHASINGFRAUDTOOLINSTALLED},
		{ASDEFS_FLAGS_DEV, CTI_TEST_DEVELOPMENTARTIFACT},
	};

	int i;
	for( i=0; i<COUNT; i++){
		if( flags & X[i][0] ){
			item->test = X[i][1];
			message_add( item );
		}
	}
}

#endif
