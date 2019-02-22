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


#include <stdint.h>
#include <sys/mman.h>
#include <errno.h>

#include "ascti_tests.h"
#include "config.h"
#include "as_ma_private.h"

#include "observations/checkhook.h"

#define ERRORBASE	40000

#define CACHE_SIZE	(4096)
#define SLOTS_MAX	64

typedef struct {
	uint32_t tuples[SLOTS_MAX * 3]; // 768 bytes
	uint32_t tuple_csum;
} layout_t;

static int _cache_lock = 0;
static layout_t* _cache_page = 0;

__attribute__((always_inline))
static void _int_encode(int slot, uint32_t val, uint32_t *tuple, int full)
{
	uint32_t mixer = (slot << 24) | (slot << 16) | (slot << 8) | slot;
	tuple[1] = val ^ mixer ^ tuple[0];

	uint32_t a = 1, b = 0, i;
	uint8_t *data = (uint8_t*)&tuple[0];
	for( i=0; i<8; i++ ){
		a = (a + data[i]) % 65521;
		b = (b + a) % 65521;
	}
	tuple[2] = ((a & 0xffff) << 16) | (b & 0xffff);

	if( full > 0 ){
		a = 1, b = 0;
		data = (uint8_t*)&_cache_page->tuples[0];
		for( i=0; i<sizeof(_cache_page->tuples); i++ ){
			a = (a + data[i]) % 65521;
			b = (b + a) % 65521;
		}
		_cache_page->tuple_csum = ((a & 0xffff) << 16) | (b & 0xffff);
	}
}

__attribute__((always_inline))
static int _int_decode(int slot, uint32_t *tuple, uint32_t *result)
{
	uint32_t a = 1, b = 0, i;
	uint8_t *data = (uint8_t*)&_cache_page->tuples[0];
	for( i=0; i<sizeof(_cache_page->tuples); i++ ){
		a = (a + data[i]) % 65521;
		b = (b + a) % 65521;
	}
	uint32_t csum = ((a & 0xffff) << 16) | (b & 0xffff);
	if( csum != _cache_page->tuple_csum ) return 1;

	a = 1, b = 0;
	data = (uint8_t*)&tuple[0];
	for( i=0; i<8; i++ ){
		a = (a + data[i]) % 65521;
		b = (b + a) % 65521;
	}
	csum = ((a & 0xffff) << 16) | (b & 0xffff);
	if( csum != tuple[2] ) return 1;

	uint32_t mixer = (slot << 24) | (slot << 16) | (slot << 8) | slot;
	*result = tuple[1] ^ tuple[0] ^ mixer;
	return 0;
}


int guarded_init()
{
	int hooked = 0, record;
	CHECK_HOOK(MMAP_NOM, hooked, record);
	CHECK_HOOK(TCL_Random, hooked, record);
	CHECK_HOOK(MPROTECT_NOM, hooked, record);
	CHECK_HOOK(guarded_uint32_get, hooked, record);
	CHECK_HOOK(guarded_uint32_set, hooked, record);
	REPORT_HOOKING(hooked, record);

	_cache_page = (layout_t*)MMAP(NULL, CACHE_SIZE, PROT_READ|PROT_WRITE, MAP_ANON|MAP_PRIVATE, -1, 0);
	if( _cache_page == MAP_FAILED ){
		ALOG("CI:ERR: guarded_init mmap");
		return error_report(ERRORBASE+__LINE__,0,1);
	}

	TCL_Random( (uint8_t*)&_cache_page->tuples[0], sizeof(_cache_page->tuples) );

	int i;
	for( i=0; i<SLOTS_MAX; i++ ){
		int o = i * 3;
		_int_encode(i, 0, &_cache_page->tuples[o], 0);
	}
	_int_encode(0, 0, &_cache_page->tuples[0], 1);

	int res = MPROTECT( _cache_page, CACHE_SIZE, PROT_NONE );
	if( res != 0 ){
		ALOG("CI:ERR: guarded_init mprotect");
		return error_report(ERRORBASE+__LINE__,errno,2);
	}

	return 0;
}

int guarded_uint32_get(int slot, uint32_t *result)
{
	ASSERT(result);
	ASSERT(slot >= 0);
	ASSERT(slot < SLOTS_MAX);

	int hooked = 0, record;
	CHECK_HOOK(TCL_Random, hooked, record);
	CHECK_HOOK(message_add, hooked, record);
	CHECK_HOOK(MPROTECT_NOM, hooked, record);
	CHECK_HOOK(guarded_uint32_get, hooked, record);
	CHECK_HOOK(guarded_uint32_set, hooked, record);
	REPORT_HOOKING(hooked, record);

	int o = slot * 3;
	int res = 1;

	// Mutex around all cache access
        while( !__sync_bool_compare_and_swap( &_cache_lock, 0, 1 ) ){}
        __sync_synchronize();

	if( MPROTECT( _cache_page, CACHE_SIZE, PROT_READ|PROT_WRITE ) != 0 ){
		ALOG("CI:ERR: guarded_get mprotect 1");
		error_report(ERRORBASE+__LINE__,errno,0);
		goto unlock;
	}

	if( _int_decode( slot, &_cache_page->tuples[o], result ) > 0 ){
		// Tampering
		ALOG("CI:ERR: guarded int checksum failed");
		ASCTI_Item_t item;
		MEMSET( &item, 0, sizeof(item) );
		item.test = CTI_TEST_APPLICATIONTAMPERINGDETECTED;
		item.subtest = _SUBTEST_INTERNAL_GUARDED;
		item.data3_type = ASCTI_DT_VRID;
		item.data3 = ERRORBASE+__LINE__;
		message_add( &item );
		goto protect;
	}

	TCL_Random( (uint8_t*)&_cache_page->tuples[o], sizeof(uint32_t) * 3 );
	_int_encode( slot, *result, &_cache_page->tuples[o], 1 );
	res = 0;

protect:
	if( MPROTECT( _cache_page, CACHE_SIZE, PROT_NONE ) != 0 ){
		ALOG("CI:ERR: guarded_get mprotect 2");
		error_report(ERRORBASE+__LINE__,errno,0);
	}

unlock:

	// Unlock mutex
        __sync_synchronize();
        _cache_lock = 0;

	return res;
}


int guarded_uint32_set(int slot, uint32_t value)
{
	ASSERT(slot >= 0);
	ASSERT(slot < SLOTS_MAX);

	int hooked = 0, record;
	CHECK_HOOK(TCL_Random, hooked, record);
	CHECK_HOOK(MPROTECT_NOM, hooked, record);
	CHECK_HOOK(guarded_uint32_get, hooked, record);
	CHECK_HOOK(guarded_uint32_set, hooked, record);
	REPORT_HOOKING(hooked, record);

	int res = 0;
	int o = slot * 3;

	// Mutex around all cache access
        while( !__sync_bool_compare_and_swap( &_cache_lock, 0, 1 ) ){}
        __sync_synchronize();

	if( MPROTECT( _cache_page, CACHE_SIZE, PROT_READ|PROT_WRITE ) != 0 ){
		ALOG("CI:ERR: guarded_set mprotect 1");
		error_report(ERRORBASE+__LINE__,errno,0);
		res = 1;
		goto unlock;
	}

	TCL_Random( (uint8_t*)&_cache_page->tuples[o], sizeof(uint32_t) * 3 );
	_int_encode( slot, value, &_cache_page->tuples[o], 1 );

	if( MPROTECT( _cache_page, CACHE_SIZE, PROT_NONE ) != 0 ){
		ALOG("CI:ERR: guarded_get mprotect 2");
		error_report(ERRORBASE+__LINE__,errno,0);
	}

unlock:

	// Unlock mutex
        __sync_synchronize();
        _cache_lock = 0;

	return res;
}

