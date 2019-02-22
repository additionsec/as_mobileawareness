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
#include "as_ma_platform.h"
#include "config.h"
#include "seed.h"
#include "as_cti.h"
#include "ascti_tests.h"

#include "observations/checkhook.h"
#include "observations_debugger.inline.c"

#if SYSTEMID == 2
// Android
#include "observations_libs.inline.c"
#endif

#define ERRORBASE	42000


void heartbeat_internal()
{
	// Execute some stuff
	observations_debugger(0, &_CONFIG.track_debug);

#if SYSTEMID == 2
	// Android
	observations_libs();
#endif
}


uint32_t heartbeat(uint32_t inp)
{
	int found = 0, record;
	CHECK_HOOK(observations_debugger, found, record);
#if SYSTEMID == 2
	CHECK_HOOK(observations_libs, found, record);
#endif
	CHECK_HOOK(heartbeat_internal, found, record);
	CHECK_HOOK(message_add, found, record);
	REPORT_HOOKING(found, record);

	heartbeat_internal();

	if( inp != (_CONFIG.scb_out ^ SEED_49) ){
		// Heartbeat failure
		ASCTI_Item_t item;
		MEMSET(&item, 0, sizeof(item));
		item.test = CTI_TEST_HEARTBEATFAILURE;
		message_add( &item );
	}

	return (_CONFIG.scb_in ^ SEED_49);
}
