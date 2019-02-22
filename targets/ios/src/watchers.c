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

#include <pthread.h>
#include <time.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>

#include <CoreFoundation/CoreFoundation.h>
#include <dispatch/dispatch.h>

#include "as_ma_platform.h"
#include "as_ma_private.h"
#include "ascti_tests.h"
#include "as_cti.h"

#include "observations/checkhook.h"
#include "observations_debugger.inline.c"
#include "observations_hooks.inline.c"

#define WAIT_SECS_NORMAL 	30ull
#define WAIT_SECS_ELEVATED	10ull
#define WAIT_SECS_CONFIRMED	3ull

#define RECHECK_INTERVAL	6

#define RESET_SECS (60 * 15)

static dispatch_queue_t _q;
static time_t _reset = 0;
static int _notfirst = 0;
static unsigned int _ctr = 0;
static uint32_t _dtrack = 0;

#define ERRORBASE	56000

static void watchers_periodic()
{
	int found = 0, record;
	CHECK_HOOK(dispatch_after, found, record);
	CHECK_HOOK(dispatch_time, found, record);
	CHECK_HOOK(watchers_periodic, found, record);
	CHECK_HOOK(time, found, record);
	//CHECK_HOOK(observations_debugger, found, record);
	//CHECK_HOOK(observations_hooks, found, record);
	CHECK_HOOK(guarded_uint32_get, found, record);
	REPORT_HOOKING(found, record);

	// Get our delay scheduling
	uint32_t level = 2;
	if( guarded_uint32_get(GUARDED_SLOT_MONLEVEL, &level) > 0 ){
		ALOG("CI:WARN: guarded monlevel get integrity issue");
		// NOTE: guarded_uint32_get reports integrity internally
	}


	//
	// Check things that can change at runtime; generally speaking, these need to be
	// super fast since we check them often.
	//

	//
	// Reset the debugger reporting cache every X minutes, so we re-report debugger present
	// on occasion
	//
	time_t now = time(0);
	if( now > _reset ){
		ALOG("CI:TAG: Resetting debugger reporting cache");
		_CONFIG.track_debug = 0;
		_dtrack = 0;
		_reset = now + RESET_SECS;
	}
	observations_debugger(1, &_dtrack);

	//
	// Rerun hook detection; we don't clear the cache for that one
	//
	_ctr++; // NOTE: it's ok if this rolls over
	int force = level;
	if( (_ctr % RECHECK_INTERVAL) == 0 ) force = 1;
	observations_hooks( (_notfirst == 0) ? 1 : 0, force);


	// Dylib detection is on-demand, but we do a secondary sync run-through
	// of just the loaded names
	if( _notfirst == 0 ){
		_notfirst = 1;
#if defined(__i386__) || defined(__x86_64__)
		// Do not run on simulator
#else
		observations_dylibs_sync();
#endif
	}

	// Schedule ourselves again
	unsigned long long wait = WAIT_SECS_CONFIRMED;
	if( level == 1 ) wait = WAIT_SECS_ELEVATED;
	else if( level == 0 ) wait = WAIT_SECS_NORMAL;

	dispatch_after( dispatch_time(DISPATCH_TIME_NOW, wait * NSEC_PER_SEC), _q, ^{
		watchers_periodic();
	});

	ALOG("CI:TAG: watcher pass done");
}


int watchers_init()
{
	int found = 0, record;
	CHECK_HOOK(dispatch_get_global_queue, found, record);
	CHECK_HOOK(dispatch_async, found, record);
	CHECK_HOOK(watchers_periodic, found, record);
	REPORT_HOOKING(found, record);

	if( _CONFIG.flag_disable_background_monitor == 0 ){
		_q = dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_BACKGROUND, 0);
		dispatch_async(_q, ^{
			watchers_periodic();
		});
	} else {
		ALOG("CI:TAG: Background monitor disabled by config");
		// Send an app-only indicator that no background monitoring is happening,
		// which may or may not be what they want.
		ASCTI_Item_t item;
		MEMSET( &item, 0, sizeof(item) );
		item.test = CTI_TEST_BACKGROUNDMONITORINGDISABLED;
		//item.flag_no_send = 1;
		message_add( &item );
	}
	return 0;
}
