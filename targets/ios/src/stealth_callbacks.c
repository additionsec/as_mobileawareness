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

#include <CoreFoundation/CoreFoundation.h>
#include <objc/runtime.h>
#include <objc/message.h>

#include "as_ma_private.h"
#include "as_ma_platform.h"
#include "config.h"
#include "as_cti.h"
#include "ascti_tests.h"
#include <pthread.h>

#include "seed.h"

#define SUCCESS_RETURN	43

__attribute__((always_inline))
inline static void _crash()
{
	uint32_t *ptr = NULL;
	// NULL deref:
	*ptr = 1;

	// Other SIGSEGV
	ptr = (uint32_t*)0xfffffffc;
	*ptr = 2;
}

static void* _crash_handler(void* arg)
{
	_crash();
	return NULL;
}

__attribute__((always_inline))
inline static int _do_call( uint8_t *scb )
{
	uint8_t *clazz = scb;
	uint8_t *meth = scb;

	while( *meth != '|' && *meth != 0 ) meth++;
	if( *meth == 0 ){ 
#ifdef TARGET_IPHONE_SIMULATOR
		ALOG_ALWAYS(" *** WARNING *** Stealth Callback definition is malformed, please regenerate your as.conf");
#endif
		goto err;
	}
	*meth = 0;
	meth++;

#ifdef TARGET_IPHONE_SIMULATOR
	ALOG_ALWAYS(" *** NOTICE *** Attempting Stealth Callback for class '%s' and method '%s'", clazz, meth);
#endif

	Class cl = objc_getClass((char*)clazz);
	if( cl == NULL ){
#ifdef TARGET_IPHONE_SIMULATOR
		ALOG_ALWAYS(" *** WARNING *** Stealth Callback class '%s' not found", clazz);
#endif
		goto err;
	}

	SEL sel = sel_registerName((char*)meth);
	if( sel == NULL || class_getClassMethod(cl, sel) == NULL ){ 
#ifdef TARGET_IPHONE_SIMULATOR
		ALOG_ALWAYS(" *** WARNING *** Stealth Callback method '%s' in class '%s' not found", meth, clazz);
#endif
		goto err;
	}

	// This form is necessary for ARM64 compatibility:
	// https://developer.apple.com/library/ios/documentation/General/Conceptual/CocoaTouch64BitGuide/ConvertingYourAppto64-Bit/ConvertingYourAppto64-Bit.html#//apple_ref/doc/uid/TP40013501-CH3-SW26
	uint32_t (*cb)(id,SEL,uint32_t) = (uint32_t (*)(id, SEL, uint32_t))objc_msgSend;
	uint32_t output = cb((id)cl, sel, (uint32_t)(_CONFIG.scb_in ^ SEED_49));
	if( output != (_CONFIG.scb_out ^ SEED_49) ){ 
#ifdef TARGET_IPHONE_SIMULATOR
		ALOG_ALWAYS(" *** WARNING *** Stealth Callback method '%s' in class '%s' did not return expected value %d", meth, clazz, _CONFIG.scb_out);
#endif
		goto err;
	}

	return SUCCESS_RETURN;
err:
	ALOG("CI:ERR: SCB!");

	ASCTI_Item_t item;
	ctiitem_setup_app( &item );
	item.test = CTI_TEST_STEALTHCALLBACKFAILURE;
	message_add( &item );
	messages_flush(); // this may not finish before we crash...

	if( _CONFIG.flag_scb_failure_crash > 0 ){
#ifdef TARGET_IPHONE_SIMULATOR
		ALOG_ALWAYS(" *** WARNING *** Crashing due to stealth callback failure configuration option enabled");
#endif
		pthread_t crash_thread;
		if( pthread_create( &crash_thread, NULL, _crash_handler, NULL ) != 0 ){
			// Couldn't spawn crash thread, so crash directly
			_crash();
		}

		// we are going to wait on the join, which should never happen
		pthread_join( crash_thread, NULL );
		// Shouldn't get here; if we do, just crash directly
		_crash();
	}
	
	return -1;
}

void stealth_callbacks()
{
	ALOG("CI:TAG: STEALTH CALLBACKS...");

	// Do we have any callbacks?
	if( _CONFIG.scb1[0] == 0 ) return;

	// Flush now, if we might crash later
	if( _CONFIG.flag_scb_failure_crash > 0 ) messages_flush();

	// Do SCB1
	int ret = _do_call(_CONFIG.scb1);
	MEMSET( _CONFIG.scb1, 0, sizeof(_CONFIG.scb1) );
	if( ret != SUCCESS_RETURN ){
		// it wasn't successful, and the response should have
		// been handled; we don't need to do scb2 if scb1 failed
		return;
	}

	// If there is no SCB2, we are done
	if( _CONFIG.scb2[0] == 0 ) return;

	// Do SCB2
	_do_call(_CONFIG.scb2);
	MEMSET( _CONFIG.scb2, 0, sizeof(_CONFIG.scb2) );
}

void stealth_callbacks_conclude()
{
}
