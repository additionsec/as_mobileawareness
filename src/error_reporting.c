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

#include <errno.h>

#include "as_ma_private.h"
#include "as_cti.h"
#include "ascti_tests.h"
#include "observations/checkhook.h"

#include "tf_netsec.h"
#include "tf_cal.h"

#include "seed.h"

#define ERRORBASE	32000
#define TIMEOUT		15000

#define TAG_PINS        7

// NOTE: the hostname, path, and SPKI pins are hardcoded here.  We are using a more direct
// SHA256 of SPKI until HPKP support comes online.

/////////////////////////////////////////////////////////////////
// Obfuscated strings
//

#define WORK_MAX	8

static const uint32_t APPLICATIONOCTETSTREAM[] = {0x3edda58d,0x11cd35ba,0x69dea58e,0x5fd33dbd,0x64c5f792,0x42c571ba,0x5a89ee3,}; // "application/octet-stream"
static const uint32_t APIADDITIONSECURITYCOM[] = {0x7cc4a58d,0x4ed132b2,0x77c3a49b,0x51d93ab4,0x67c8b49d,0x41c634e9,0x6abdbb0,}; // "api.additionsecurity.com"
static const uint32_t ASMA2ER[] = {0x3fdeb4c3,0x4b9d68fc,0x1ce0e5c4,}; // "/asma/2/er"

#define _STR_START      0x52add5ec
#define _S(nom,x) _decode((sizeof(nom)/4)-1,nom,x)


/////////////////////////////////////////////////////////////////
// Pin-related handling
//

typedef struct {
	uint8_t hash[TCL_SHA256_DIGEST_SIZE];
	int matched;
} _pin_state_t;

static TFTLV_CALLBACK_DEF(_pincallback){
	// tag, len, data, state

	// We only care about HPKP pins
	if( tag != TAG_PINS ) return TFTLV_CB_RET_CONTINUE;

	ASSERT(state);
	_pin_state_t *st = (_pin_state_t*)state;
	// If we've already matched, we're done
	if( st->matched ) return TFTLV_CB_RET_STOP;

	ASSERT(len >= 32);
	if( MEMCMP(st->hash, data, TCL_SHA256_DIGEST_SIZE) == 0 ){
		ALOG("CI:TAG: ER pin matched for %s", (char*)&data[TCL_SHA256_DIGEST_SIZE]); 
		st->matched++;
		return TFTLV_CB_RET_STOP;
	}

	return TFTLV_CB_RET_CONTINUE;
}


/////////////////////////////////////////////////////////////////
// Cert-related handling
//

static void _cert_failed_callback(void *req, int is_proxy, uint8_t *cert, uint32_t certlen)
{
	ASSERT(req);
	TFN_WebRequest_t *request = (TFN_WebRequest_t*)req;

	if( is_proxy ){
		// NOT-MVP-TODO: report proxy pin errors
	} else {
		// NOTE: cert can be NULL, certlen can be 0
		ssl_violation( (char*)request->hostname, cert, certlen );
	}
}

static int _cert_callback(void* req, uint8_t *subject, uint32_t depth, int is_proxy,
	uint8_t *cert, uint32_t cert_len, 
	uint8_t *spki, uint32_t spki_len)
{
	ASSERT(req);
	ASSERT(cert);
	ASSERT(spki);

	// Ignore proxy certs (always allowed)
	if( is_proxy ) return TFN_CERT_ALLOW;

	_pin_state_t st;
	st.matched = 0;

	// Hash the SPKI
	TCL_SHA256( spki, spki_len, st.hash );

	// Check against our extensible pins
	if( _CONFIG.flag_configured > 0 ){
		int res = TFTLV_Walk_Mem( &_CONFIG.tlv_keys, &_pincallback, &st );
		if( res != TFTLV_RET_OK ){
			ALOG("CI:ERR: ER pin walk failed %d", res); 
			return error_report(ERRORBASE+__LINE__,res,TFN_CERT_PASS);
		}
		if( st.matched > 0 ) return TFN_CERT_ALLOW;
	}

	return TFN_CERT_PASS;
}

struct _sender_args {
	uint32_t err, err2;
};

static void *_error_send_thread_handler( void *arg )
{
	int found = 0, record;
	CHECK_HOOK(_cert_callback, found, record);
	CHECK_HOOK(_cert_failed_callback, found, record);
	CHECK_HOOK(ssl_violation, found, record);
	CHECK_HOOK(TCL_SHA256, found, record);
	CHECK_HOOK(TFTLV_Walk_Mem, found, record);
	CHECK_HOOK(proxy_setup, found, record);
	CHECK_HOOK(TFN_DNS_Lookup, found, record);
	CHECK_HOOK(TFN_Web_Request, found, record);
	CHECK_HOOK(_pincallback, found, record);
	REPORT_HOOKING(found, record);

	// Copy our arg data locally, then FREE() the arg so we don't risk leaking it
	struct _sender_args *_args = (struct _sender_args*)arg;
	uint32_t err = _args->err;
	uint32_t err2 = _args->err2;
	FREE(arg);

	uint32_t work[WORK_MAX]; // For string decoding
	uint32_t hostname[WORK_MAX];
	uint32_t pq[WORK_MAX];

        TFN_WebRequest_t req;
	char post_[5] = {'P',0,'S',0,0};

	struct sockaddr_in sin;
	uint8_t resp[256];
	int using_proxy = 0;

	// Format: 6 uint32_t + org_id + 256 app + 256 errfp
	uint8_t err_data[ (6 * sizeof(uint32_t)) + sizeof(_CONFIG.id_org) + 256 + 256 ];
	int res;

	// Control flow flattening
	uint32_t seed = SEED_START;
	while(1){
		uint32_t start = _SEED_NEXT(seed);

		switch(start){
		case SEED_1:
			_S(APIADDITIONSECURITYCOM, hostname);
			break;

		case SEED_2:
			_S(ASMA2ER, pq);
			break;

		case SEED_3:
        		MEMSET( &req, 0, sizeof(req) );
			break;
	
		case SEED_4:
			post_[3] = 'T';
			post_[1] = 'O';
			req.response_data = resp;
			req.response_data_max = (uint32_t)sizeof(resp);
			break;

		case SEED_5:
        		req.flags = TFN_WEBREQUEST_FLAG_SSL;
        		req.timeout_ms = TIMEOUT;
        		req.hostname = (char*)hostname;
			req.port = 443;
        		req.request_method = post_;
        		req.request_pq = (char*)pq;
        		req.request_data_ctype = _S(APPLICATIONOCTETSTREAM, work);
			break;

		case SEED_6:
			if( _CONFIG.flag_disable_proxy == 0 ){
				using_proxy = proxy_setup( &req, 0 );
			}
			break;

		case SEED_7:
			if( using_proxy == 0 ){
				if( TFN_DNS_Lookup( (char*)hostname, 443, &req.destination ) != 0 ){
					//ALOG("CI:WARN: Unable to lookup error_report DNS");
					return NULL;
				}
			}
			break;

		case SEED_8:
			req.cert_callback = _cert_callback;
			req.cert_failed_callback = _cert_failed_callback;
			break;

		case SEED_9:
			break;

		case SEED_10:
		{
			// Dynamically look up the defs value
			// NOTE: these are expected in little-endian form:
			uint32_t dat[6] = { SYSTEMID, ASVERSION, _CONFIG.ts_config, 
				TFDefs_Version( &_CONFIG.defs_as ), err, err2 };
			MEMCPY( err_data, dat, sizeof(dat) );
			uint8_t *ptr = &err_data[ sizeof(dat) ];

			MEMCPY( ptr, _CONFIG.id_org, sizeof(_CONFIG.id_org) );
			ptr += sizeof(_CONFIG.id_org);

			if( _CONFIG.pkg_sz > 255 ){
				*ptr = (uint8_t)255;
				ptr++;
				MEMCPY( ptr, _CONFIG.pkg, 255 );
				ptr += 255;
			} else {
				// Note: size may be zero
				*ptr = (uint8_t)(_CONFIG.pkg_sz & 0xff);
				ptr++;
				if( _CONFIG.pkg_sz > 0 ){
					MEMCPY( ptr, _CONFIG.pkg, _CONFIG.pkg_sz );
					ptr += _CONFIG.pkg_sz;
				}
			}

			size_t s = STRLEN((const char*)_CONFIG.err_fp);
			if( s > 255 ) s = 255;
			*ptr = (uint8_t)(s & 0xff);
			ptr++;
			MEMCPY( ptr, _CONFIG.err_fp, s );
			ptr += s;

        		req.request_data = (uint8_t*)err_data;
        		req.request_data_len = (uint32_t)(ptr - err_data);
		}
			break;

		case SEED_11:
			break;

		case SEED_12:
        		ALOG("CI:TAG: Sending error report for %d/%d", err, err2);
        		res = TFN_Web_Request( &req );
			break;

		case SEED_13:
			if( res != TFN_SUCCESS ){
				ALOG("CI:WARN: Error sending error report; errno=%d res=%d dbg=%d",
					errno, res, req.error_debug);

				if( res == TFN_ERR_PINNOTCHECKED ){
					// TODO: is this tampering?
					ssl_violation( (char*)hostname, NULL, 0 );
				}
			} else {
				ALOG("CI:TAG: error report sent");
			}
			break;

		case SEED_14:
			return NULL;
		} // switch
	}

	return NULL;
}


#define CACHE_MAX 16
static uint32_t _cache[CACHE_MAX] = {0};
static uint8_t _cache_i = 0;
static int _cache_lock = 0;

int error_report( uint32_t err, uint32_t err2, int ret )
{
	ALOG("CI:ERR: !!ERROR %d/%d", err, err2);
	ALOG_ALWAYS("E/%d/%d", err, err2);

	int found = 0, record;
	CHECK_HOOK(pthread_attr_init, found, record);
	CHECK_HOOK(pthread_attr_setdetachstate, found, record);
	CHECK_HOOK(_error_send_thread_handler, found, record);
	CHECK_HOOK(pthread_create, found, record);
	CHECK_HOOK(error_report, found, record);
	REPORT_HOOKING(found, record);

	//
	// Make sure we're not looping/flooding (seen it on one rare occasion)
	//

        // Lock the cahce (simple spinlock)
        while( !__sync_bool_compare_and_swap( &_cache_lock, 0, 1 ) ){}
        __sync_synchronize();

	found = 0;

	int i = 0;
	for( i=0; i<CACHE_MAX; i++){
		if(_cache[i] == err ) found++;
	}

	if( found == 0 ){
		_cache[_cache_i] = err;
		_cache_i++;
		if(_cache_i >= CACHE_MAX) _cache_i=0;
	}

	// Unlock the cache
        __sync_synchronize();
        _cache_lock = 0;

	if( found > 0 ) return ret;


	// We have to network off the main thread, so spawn an on-demand thread
	if( _CONFIG.flag_disable_errors == 1 ) return ret;

	// NOTE: EVERYTHING HERE IS BEST EFFORT; if we hit
	// a failure, we just won't send.

	pthread_attr_t attr;
	if( pthread_attr_init( &attr ) != 0) return ret;
	if( pthread_attr_setdetachstate( &attr, PTHREAD_CREATE_DETACHED ) != 0 )
		return ret;

	// One of the few places we actually use MALLOC()
	struct _sender_args *args = (struct _sender_args*)MALLOC(sizeof(struct _sender_args));
	if( args == NULL ) return ret;
	// NOTE: the thread will FREE() this after it's done

	args->err = err;
	args->err2 = err2;

	pthread_t error_sender_thread;
	if( pthread_create( &error_sender_thread, &attr, _error_send_thread_handler, args ) != 0 ){
		// Thread wasn't spawned, so we have to clean up our MALLOC() to not mem leak
		FREE(args);
	}

	return ret;
}
