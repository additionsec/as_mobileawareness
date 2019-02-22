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

#ifndef _AS_MA_PLATFORM_H_
#define _AS_MA_PLATFORM_H_

#include <jni.h>
#include <stdint.h>
#include <pthread.h>

#include <android/asset_manager.h>

#include "config.h"

#include "tf_cal.h"

#include <android/log.h>
#define ALOG_ALWAYS(...) __android_log_print(ANDROID_LOG_ERROR, "AS", __VA_ARGS__)
#ifdef DEBUGLOG
#define ALOG(...) __android_log_print(ANDROID_LOG_ERROR, "AS", __VA_ARGS__)
#else
#define ALOG(...)
#endif


#define FLAG_INSTRUMENTATION	1
#define FLAG_DEBUGMODE		2
#define FLAG_DEBUGGABLE		4

// NOTE: _FILE & _IMAGE matches across IOS & Android:
#define _SUBTEST_APPMEASURE_FILE      1
#define _SUBTEST_APPMEASURE_IMAGE       3
#define _SUBTEST_APPMEASURE_APK		10
#define _SUBTEST_AOSP_PLATFORM_SIGNED	89
#define _SUBTEST_NP_PROPERTY	100
#define _SUBTEST_NP_CM		101
#define _SUBTEST_NP_AFTERMARKET	102

#define HOOK_CACHE_MAX     128

#ifdef __cplusplus
extern "C" {
#endif

// Standalone integrity value:
extern uint8_t _SA_DIGEST[];

#include <sys/system_properties.h>
int property_get(const char name[PROP_NAME_MAX], char value[PROP_VALUE_MAX] );

void stealth_callbacks_load( JNIEnv *env );
void observations_java();
void *_inotify_thread_handler( void *arg );
int proxy_init( JNIEnv *env );

int mutex_timedlock( pthread_mutex_t *mutex, struct timespec *maxwait );

int bootstrap_pre( JNIEnv *env, const uint8_t uuid[32], 
	/*NOT CONST*/ uint8_t *config, uint32_t config_len,
        void(*callback)(int,int,ASCTI_Item_t*) );

#ifdef __cplusplus
} // extern C
#endif


struct _platform_config {
	int	api;
	int 	fd_self_status;

	uint8_t *art_gdebuggeractive;
	void 	*art_isdebuggeractive;
	void 	*dvm_dbg_isdebuggerconnected;

	// cached vm reference; android only has one and it never goes out of
	// scope, so we can cache it safely
	JavaVM 	*vm;

	// A ref-counted system context object
	jobject o_ctx;

	// A ref-counted packagemanager object
	jobject o_pm;

	// Native asset manager object
	AAssetManager *am;

#ifdef UNITY
	// Defs memory pointer
	const uint8_t *defs;
	uint32_t defs_len;
#endif

	// Due to android bugginess, FindClass fails in another thread, so going
	// to do the lookups in the main thread, cache them, and re-use them later
	jclass 	jc_scb1, jc_scb2;
	jmethodID jm_scb1, jm_scb2;

	// Ditto for VMDebug if we are ARM on x86
	jclass jc_vmd;
	jmethodID jm_idc;

	// path to APK
	char	apk[ASMA_PKG_MAX];

	// path to lib
	char	asmalib[ASMA_PATH_MAX];

	// code segment
	void 	*code_start;
	uint32_t code_len;
	uint8_t  code_digest[TCL_SHA1_DIGEST_SIZE];

	// misc flags
	uint32_t is_cyanogenmod : 1;
	uint32_t is_x86_emulating_arm : 1;
	uint32_t adbd : 1;
};

extern struct _platform_config _PLATFORM_CONFIG;

#endif
