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

#include "as_cti.h"
#include "ascti_tests.h"
#include "as_ma_private.h"

#include "tf_pkcs7.h"
#include "tf_cal.h"
#include PLATFORM_H

#define CACHE_SIZE	4

#define ERRORBASE	37000

typedef struct {
	uint32_t host;
	uint8_t spki[TCL_SHA256_DIGEST_SIZE];
} _SSL_CacheItem_t;

static _SSL_CacheItem_t _cache[CACHE_SIZE];
static int _cache_lock = 0;

void ssl_violation( char *hostname, uint8_t *cert, uint32_t cert_len )
{
	ASSERT( hostname );
	// NOTE: cert can be NULL, cert_len can == 0

	// Hash the hostname
	size_t hostname_len = STRLEN(hostname);
	uint32_t hostname_crc = TCL_CRC32( (uint8_t*)hostname, hostname_len );

	// Set up our pinning violation item
	ASCTI_Item_t item;
	MEMSET( &item, 0, sizeof(item) );

	item.test = CTI_TEST_SSLPINVIOLATION;
	item.data1 = hostname;
	item.data1_len = hostname_len;
	item.data1_type = ASCTI_DT_HOSTNAME;

	// Do we have a cert?
	if( cert == NULL || cert_len == 0 ){
		// No cert, so just indicate the hostname and be done
		message_add( &item );
		return;
	}

	// We have a cert, so process it

	uint8_t *spki;
	uint32_t spki_len;
	char subject[TFS_PKCS7_SUBJECT_SIZE];

	int ret = TFS_PKCS7_X509_Parse( cert, cert_len, &spki, &spki_len, subject, NULL );
	if( ret == TFS_PKCS7_ERR_OK ){

		// We've parsed it, so include the SPKI hash
		uint8_t spki_hash[TCL_SHA256_DIGEST_SIZE];
		TCL_SHA256( spki, spki_len, spki_hash );
		item.data2 = spki_hash;
		item.data2_len = sizeof(spki_hash);
		item.data2_type = ASCTI_DT_HPKP;

		message_add( &item );

		// Get the lock
		while( !__sync_bool_compare_and_swap( &_cache_lock, 0, 1 ) ){}
		__sync_synchronize();
		int i;
#if 0
		do { i = pthread_mutex_lock(&_cache_lock); } while(i != 0);
#endif

		// check the cache for this host/spki combo
		int found = 0;
		for( i=0; i<CACHE_SIZE; i++ ){
			// Check for hostname match:
			if( _cache[i].host != hostname_crc ) continue;

			// Hostname matches; check for spki match:
			if( MEMCMP( _cache[i].spki, spki_hash, TCL_SHA256_DIGEST_SIZE ) == 0 ){
				// Hostname and spki match, so we've reported this already; we're done
				ALOG("CI:TAG: SPKI found in cache, not reporting");
				found++;
#if 0
				do { i = pthread_mutex_unlock(&_cache_lock); } while(i != 0);
				return;
#endif
			}
		}
		// Don't hold the lock over the send
		//do { i = pthread_mutex_unlock(&_cache_lock); } while(i != 0);
		__sync_synchronize();
		_cache_lock = 0;

		if( found > 0 ) return;

		// If we get here, it's not in the cache.  So we need to report it and add to cache.
		MEMSET( &item, 0, sizeof(item) );

		item.test = CTI_TEST_SSLPINVIOLATIONCERTIFICATE;
		item.data1 = hostname;
		item.data1_len = hostname_len;
		item.data1_type = ASCTI_DT_HOSTNAME;

		item.data2 = cert;
		item.data2_len = cert_len;
		item.data2_type = ASCTI_DT_X509;
	
		message_add( &item );

		// Get the cache lock again
		//do { i = pthread_mutex_lock(&_cache_lock); } while(i != 0);
		while( !__sync_bool_compare_and_swap( &_cache_lock, 0, 1 ) ){}
		__sync_synchronize();

		// Find an empty slot in the cache
		for( i=0; i<CACHE_SIZE; i++ ){
			//uint32_t *u32 = (uint32_t*)_cache[i].host;
			// If the first 8 bytes are all zeros, we consider this an empty slot
			//if( u32[0] == 0 && u32[1] == 0 ) break;
			if( _cache[i].host == 0 ) break;
		}

		// If we enumerated through the whole cache, then just randomly replace one.
		// Since we don't maintain an overwrite counter, this is the next best choice
		if( i >= CACHE_SIZE ){
			uint8_t drop;
			if( TCL_Random( &drop, 1 ) == 0 ) i = drop % CACHE_SIZE;
			else i = (CACHE_SIZE - 1);
		}
		//MEMCPY( _cache[i].host, hostname_digest, sizeof(hostname_digest) );
		_cache[i].host = hostname_crc;
		MEMCPY( _cache[i].spki, spki_hash, sizeof(spki_hash) );

		//do { i = pthread_mutex_unlock(&_cache_lock); } while(i != 0);
		__sync_synchronize();
		_cache_lock = 0;

	} else {
		error_report(ERRORBASE+__LINE__,ret,0);
		// We couldn't parse cert, so send original message w/out SPKI hash so app is at least
		// informed of *something*
		message_add( &item );
	}

}
