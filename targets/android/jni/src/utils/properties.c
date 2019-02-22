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

#include <stdlib.h>
#include <dlfcn.h>
#include <sys/system_properties.h>

#include "as_ma_private.h"
#include "as_ma_platform.h"

#define ERRORBASE 13000

#define WORK_MAX 7

static const uint32_t __SYSTEM_PROPERTY_GET[] = {0x2bde8ab3,0x1dca0d9e,0x25c5829c,0x2ce1cb0,0x28cca492,0x63ad47bc,}; // "__system_property_get"

#define _STR_START      0x52add5ec
#define _S1(nom) _decode((sizeof(nom)/4)-1,nom,work1)

// Modeled after https://codereview.chromium.org/393923002/

static int (*___system_property_get)(const char*, char*) = NULL;
static int resolve_fail = 0;

int property_get(const char name[PROP_NAME_MAX], char value[PROP_VALUE_MAX] )
{
	// NOTE: we don't lock around this, which conceptually means
	// multi-thread use could init the symbol twice, but that's
	// ok ... other than being less efficient, the total operation
	// is idempotent.
	if( ___system_property_get == NULL ){
		uint32_t work1[WORK_MAX];
		if( resolve_fail > 0 ) return -1;
		___system_property_get = dlsym(RTLD_DEFAULT, _S1(__SYSTEM_PROPERTY_GET));
		if( ___system_property_get == NULL ) { 
			ALOG("CI:ERR: dlsym propget"); 
			resolve_fail++;
			return error_report(ERRORBASE+__LINE__,0,-1);
		}
	}
	return ___system_property_get(name, value);
}
