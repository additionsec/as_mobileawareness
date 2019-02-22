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

#include <stdio.h>

#include "as_ma_private.h"
#include "config.h"
#include "observations.h"

#include "ascti_tests.h"
#include "as_defs_flags.h"

#define ERRORBASE_IC 26000

__attribute__((always_inline))
static inline void observations_item_common( uint8_t section, ASCTI_Item_t *item, uint32_t flags )
{

	// The common core items
#define COMMON_COUNT 16
	const uint32_t COMMON[][2] = {
               	// Flag, test
		{ASDEFS_FLAGS_APF, CTI_TEST_APPPURCHASINGFRAUDTOOLINSTALLED},
		{ASDEFS_FLAGS_GCT, CTI_TEST_GAMECHEATTOOLINSTALLED},
               	{ASDEFS_FLAGS_HT, CTI_TEST_HACKINGTOOLINSTALLED},
		{ASDEFS_FLAGS_PGA, CTI_TEST_PRIVILEGEPROVIDINGAPPLICATIONINSTALLED},
		{ASDEFS_FLAGS_EMU, CTI_TEST_SYNTHETICSYSTEMARTIFACT},
               	{ASDEFS_FLAGS_DBG, CTI_TEST_DEBUGINSTRUMENTATIONARTIFACT},
               	{ASDEFS_FLAGS_ATT, CTI_TEST_APPLICATIONTAMPERINGTOOLINSTALLED},
               	{ASDEFS_FLAGS_ATD, CTI_TEST_APPLICATIONTAMPERINGDETECTED},
		{ASDEFS_FLAGS_NP, CTI_TEST_NONPRODUCTIONSYSTEMARTIFACT},
		{ASDEFS_FLAGS_SEF, CTI_TEST_SECURITYEXPECTATIONFAILURE},
              	{ASDEFS_FLAGS_SS2, CTI_TEST_SECURITYHIDINGTOOLINSTALLED},
		{ASDEFS_FLAGS_TEST, CTI_TEST_TESTAUTOMATIONTOOLINSTALLED},
               	{ASDEFS_FLAGS_SS, CTI_TEST_SECURITYSUBVERSIONTOOLINSTALLED},
               	{ASDEFS_FLAGS_MAL, CTI_TEST_KNOWNMALWAREARTIFACTDETECTED},
		{ASDEFS_FLAGS_CERT, CTI_TEST_PUBLICSTOLENCERTSIGNERPRESENT},
		{ASDEFS_FLAGS_ROOT, CTI_TEST_SYSTEMROOTJAILBREAK},
	};

      	int i;
	int match = 0;
       	for( i=0; i<COMMON_COUNT; i++){
               	if( flags & COMMON[i][0] ){
			match++;
			int fl_ = item->flag_no_send;
#if 0
			// We don't send AV and EMM to backend
			if( COMMON[i][0] == ASDEFS_FLAGS_AV || COMMON[i][0] == ASDEFS_FLAGS_EMM )
				item->flag_no_send = 1;
#endif
                       	item->test = COMMON[i][1];
                       	message_add( item );
			item->flag_no_send = fl_;
               	}
       	}

	// We ignore these, but we dont' want them to trigger non-match errors
	if( (flags & ASDEFS_FLAGS_AV) | (flags & ASDEFS_FLAGS_EMM) ) match++;

	if( match == 0 ){
		// We didn't match a flag; typically, this means we didn't align the data model correctly
		error_report(ERRORBASE_IC+__LINE__, flags, 0);
	}
}

#endif
