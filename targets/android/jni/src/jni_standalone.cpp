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

#include <jni.h>
#include <stdint.h>

#include "tf_cal.h"
#include "as_ma_platform.h"
#include "as_mobileawareness.h"

extern "C" {

// This is the stored integrity value of the whole library, which we
// check during processing when in standalone mode
uint8_t _SA_DIGEST[ sizeof(uint32_t) + TCL_ECC_SIZE ] = { 
	'I','N','T','E','G','R','I','T','Y',0,0,0,0,0,0,0, 
	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
	0,0,0,0
};


// According to android docs, the JavaVM* is lifetime, never goes out of
// context, and is generally safe to cache.  That's not the case for all
// Java, but it is for Android.
static JavaVM *_vm = NULL;

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved)
{
	_vm = vm;
//#ifndef UNITY
	return AS_JNI_OnLoad(vm, reserved);
//#else
	//return JNI_VERSION_1_6;
//#endif
}


#ifdef UNITY
//
// Special helper case for Unity.
//
int AS_Initialize_Direct( 
	const uint8_t *config, uint32_t config_len,
	const uint8_t *defs, uint32_t defs_len,
	void(*callback)(int,int,uint8_t*,uint32_t,uint8_t*,uint32_t) )
{
	//
	// Make sure the JNI_OnLoad was called, so we have a vm reference
	//
	// NOTE: callback is allowed to be NULL
	if( _vm == NULL || config == NULL || defs == NULL ){
		ALOG("CI:ERR: Direct prereq");
		return AS_ERR_GENERAL;
	}

	//
	// For Direct/Unity, we are going to use our native ID generator
	//
	uint8_t uuid[32];
	int ret = AS_UUID_Default_Serial( uuid );
	if( ret != AS_SUCCESS ){
		ALOG("CI:ERR: Direct default serial");
		return ret;
	}

	//
	// We need to get an env; NOTE: this must already be an attached
	// thread, or it will fail down the road.
	//
	JNIEnv *env;
	ret = _vm->GetEnv((void**)&env, JNI_VERSION_1_6);
	if( ret != JNI_OK ){ // Inclusive of JNI_EDETACHED
		ALOG("CI:ERR: Direct getenv = %d", ret);
		return AS_ERR_GENERAL;
	}

	//
	// Save our defs pointer
	//
	_PLATFORM_CONFIG.defs = defs;
	_PLATFORM_CONFIG.defs_len = defs_len;

	//
	// We got what we need
	//
	return AS_Initialize( env, uuid, config, config_len, callback );
}
#endif

} // extern C

