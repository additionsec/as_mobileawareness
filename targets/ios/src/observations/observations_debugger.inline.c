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

#ifndef _OB_DEBUGGER_INLINE_C_
#define _OB_DEBUGGER_INLINE_C_

#include <CoreFoundation/CoreFoundation.h>
#include <objc/runtime.h>
#include <objc/message.h>
#include <sys/time.h>

#include "as_ma_private.h"
#include "ascti_tests.h"
#include "as_defs_flags.h"

#include <sys/proc.h>
#include <sys/sysctl.h>
#include <sys/types.h>
#include <unistd.h>

#include <mach/task.h>
#include <mach/mach_init.h>
#include <stdbool.h>

#define ERRORBASE_OBD 50000

#define D_CACHE_MAX 8
static volatile uint64_t _d_cache[D_CACHE_MAX] = {0};
static volatile uint8_t  _d_cache_ptr = 0;

__attribute__((always_inline))
static inline void observations_debugger(int looping, uint32_t *track)
{
	ASCTI_Item_t item;

	//
	// Check our kernel process info
	//
	struct kinfo_proc info;
	size_t infosz = sizeof(info);
	int ctl[4]={CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid()};

	if( ((*track) & 1) == 0 ){
	  ALOG("CI:TAG: debugger check KP");
	  if( SYSCTL( ctl, 4, &info, &infosz, NULL, 0 ) == 0 ){

		// http://unix.superglobalmegacorp.com/Net2/newsrc/sys/proc.h.html
		if( (info.kp_proc.p_flag & P_TRACED) || info.kp_proc.p_debugger || info.kp_proc.p_traceflag )
		{
			ALOG("CI:TAG: DEBUGGER DETECTED (KP)");
			MEMSET(&item, 0, sizeof(item));
			item.test = CTI_TEST_DEBUGINSTRUMENTATIONARTIFACT;
			item.subtest = 35;
			message_add( &item );
			*track |= 1;
		}
		if( (info.kp_proc.p_flag & P_DISABLE_ASLR) ){
			ALOG("CI:TAG: ASLR DISABLED");
			// Debugger can disable it, or it's rooted
			MEMSET(&item, 0, sizeof(item));
			item.test = CTI_TEST_SECURITYEXPECTATIONFAILURE;
			item.subtest = 36;
			item.data3 = ERRORBASE_OBD+__LINE__;
			item.data3_type = ASCTI_DT_VRID;
			message_add( &item );
			*track |= 1;
		}
	  } else { 
		ALOG("CI:ERR: sysctl KERN_PROC"); 
		if( ((*track) & 2) == 0 ){
			uint32_t id = ERRORBASE_OBD+__LINE__;
			error_report( ERRORBASE_OBD+__LINE__, 0, 0);
			MEMSET(&item, 0, sizeof(item));
			item.test = CTI_TEST_SECURITYOPERATIONFAILED;
			item.data3 = ERRORBASE_OBD+__LINE__;
			item.data3_type = ASCTI_DT_VRID;
			message_add( &item );
			*track |= 2;
		}
	  }
	}


	//
	// Check for exception handlers by debuggers
	//
	// https://zgcoder.net/ramblings/2016/01/30/osx-debugger-detection.html
	if( ((*track) & 4) == 0 ){
		mach_msg_type_number_t count = 0;
		exception_mask_t masks[EXC_TYPES_COUNT];
		mach_port_t ports[EXC_TYPES_COUNT];
		exception_behavior_t behaviors[EXC_TYPES_COUNT];
		thread_state_flavor_t flavors[EXC_TYPES_COUNT];
		exception_mask_t mask = EXC_MASK_ALL & ~(EXC_MASK_RESOURCE | EXC_MASK_GUARD);

		ALOG("CI:TAG: debugger check ExH");

		// NOT-MVP-TODO: should we obfuscation task_get_expection_ports?
		if( task_get_exception_ports(mach_task_self(), mask, masks, &count, ports, 
			behaviors, flavors) == KERN_SUCCESS ){
			for (mach_msg_type_number_t portIndex = 0; portIndex < count; portIndex++) {
				if (MACH_PORT_VALID(ports[portIndex])) {
					ALOG("CI:TAG: DEBUGGER DETECTED (ExH)");
					MEMSET(&item, 0, sizeof(item));
					item.test = CTI_TEST_DEBUGINSTRUMENTATIONARTIFACT;
					item.subtest = 37;
					message_add( &item );
					*track |= 4;
					break;
				}
			}
		} else {
			if( ((*track) & 8) == 0 ){
				ALOG("CI:ERR: get_exception_ports");
				uint32_t id = ERRORBASE_OBD+__LINE__;
				error_report( ERRORBASE_OBD+__LINE__, 0, 0);
				MEMSET(&item, 0, sizeof(item));
				item.test = CTI_TEST_SECURITYOPERATIONFAILED;
				item.data3 = ERRORBASE_OBD+__LINE__;
				item.data3_type = ASCTI_DT_VRID;
				message_add( &item );
				*track |= 8;
			}
		}
	}
}

#endif
