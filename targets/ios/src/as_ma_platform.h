#ifndef _AS_MA_PLATFORM_H_
#define _AS_MA_PLATFORM_H_

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

#define _SUBTEST_APPMEASURE_FILE	1
#define _SUBTEST_APPMEASURE_MH		2
#define _SUBTEST_APPMEASURE_IMAGE	3

#include "observations/checkhook.h"

#include <asl.h>
#include <stdio.h>
#define ALOG_ALWAYS(...) do { asl_log(NULL, NULL, ASL_LEVEL_ERR, __VA_ARGS__); printf(__VA_ARGS__); } while(0)
#ifndef NDEBUG
#define ALOG(...) asl_log(NULL, NULL, ASL_LEVEL_ERR, __VA_ARGS__)
#else
#define ALOG(...)
#endif

#if defined(__i386__) || defined(__x86_64__)
#ifndef TARGET_IPHONE_SIMULATOR
#define TARGET_IPHONE_SIMULATOR
#endif
#else
#undef TARGET_IPHONE_SIMULATOR
#endif

#define HOOK_CACHE_MAX     128

void observations_dylibs();
void observations_dylibs_sync();

struct _platform_config {
	// For Direct (used by Unity et al)
	const uint8_t *defs;
	uint32_t defs_len;
	const uint8_t *config;
	uint32_t config_len;
};

extern struct _platform_config _PLATFORM_CONFIG;

#endif
