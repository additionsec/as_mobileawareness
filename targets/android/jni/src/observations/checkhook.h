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

#ifndef _CHECKHOOK_H_
#define _CHECKHOOK_H_

#include "ascti_tests.h"


#if defined(__i386__)

#if defined(__LP64__)
// x86_64
#define CHECK_HOOK(sym,found,record)	\
	do { if(found==0){ \
		uint32_t *a = (uint32_t*)sym; \
		uint32_t av = a[0] & 0xf0000fff; \
		uint32_t bv = a[1] & 0x000000ff; \
		if( (av == 0xf00003e9 || av == 0xe00003e9 ) && (bv == 0xff || bv == 0xfe ) ){ found++; record = ERRORBASE+__LINE__; }\
	}} while(0)

#else
// x86
#define CHECK_HOOK(sym,found,record)	\
	do { if(found==0){ \
		uint32_t *a = (uint32_t*)sym; \
		uint32_t av = a[0] & 0xf0000fff; \
		uint32_t bv = a[1] & 0x0000ffff; \
		if( (av == 0xf0000fe9 || av == 0xe0000fe9 ) && (bv == 0x90ff || bv == 0x90fe ) ){ found++; record = ERRORBASE+__LINE__; }\
	}} while(0)

#endif // x86 vs x86_64

#else
// arm or arm64

#if defined(__LP64__)
// arm64

#define CHECK_HOOK(sym,found,record)	\
	do { if(found == 0){ \
			uintptr_t x = (uintptr_t)sym; \
			uint32_t *a = (uint32_t*)(x & ~1); \
			if( a[1] == 0xd61f0200 && (a[0] == 0x58000050 || (a[0] & 0x0fffff0f) == 0x00ff8a00) ) { found++; record = ERRORBASE+__LINE__; } \
	}} while(0)

#else
// arm32

#define CHECK_HOOK(sym,found,record)	\
	do { if(found == 0){ \
			uintptr_t x = (uintptr_t)sym; \
			uint32_t *a = (uint32_t*)(x & ~1); \
			if( (x & 1) == 0 ){  \
				if( a[0] == 0xe51ff004 	|| a[0] == 0xe7f001f0 ){ found++; record = ERRORBASE+__LINE__; } \
			} else { \
				uint16_t *b = (uint16_t*)(x & ~1); \
				if( ( b[0] & 0xff00 ) == 0xbe00 || (a[0] & 0xfff0ffff) == 0xf000f8df) { found++; record = ERRORBASE+__LINE__; } \
			} \
	}} while(0)

#endif // arm or arm64

#endif // x86 or arm



// TODO: add analytics coalesce/cache?
#define REPORT_HOOKING(found,record) \
	if( found > 0 ){\
		ALOG("CI:WARN: internal hooking at %d", record); \
		ASCTI_Item_t item; \
		MEMSET(&item, 0, sizeof(item)); \
		item.test = CTI_TEST_APPLICATIONTAMPERINGDETECTED; \
		item.subtest = _SUBTEST_INTERNAL_HOOKCHECK; \
		item.data3_type = ASCTI_DT_VRID; \
		item.data3 = record; \
		message_add( &item ); \
	}


#endif
