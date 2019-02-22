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

#include <time.h>

#include "as_ma_private.h"
#include "as_license.h"
#include "observations/checkhook.h"

#include "tf_tlv.h"
#include "tf_netsec.h"
#include "tf_cal.h"
//#include "tf_qf.h"

#include "seed.h"

#define ERRORBASE_CP	34000
#define MAGIC_SIZE	4
#define MAGIC		0x0fadd5ec


#define TAG_MINVER	1
#define TAG_ORG		2
#define TAG_FLAGS	3
#define TAG_GENTS	4
#define TAG_LIC		5
#define TAG_MSGURL	6
#define TAG_PINS	7
#define TAG_SCB		8
#define TAG_SET_FLAGS	9
#define TAG_KEY_ECC	128
#define TAG_KEY_RSA	129

// This is a granular break-out of the TLV sig blob
typedef struct __attribute__((packed, aligned(4))) {
	uint8_t ecc[64];
	uint8_t rsa[256];
	uint8_t otp[TFTLV_OTP_SIZE];
} _config_sig_t;

// A state object for config TLV walking
typedef struct {
	int res;
	uint32_t licensed : 1;
	uint32_t flagged : 1;
	uint32_t org : 1;
} _config_parse_state_t;

// A state object for config keys TLV walking
typedef struct {
	uint16_t tried;
	uint16_t verified;
	_config_sig_t *sig;
	uint8_t *digest;
} _config_sig_state_t;


// Walk callback for config TLV
TFTLV_CALLBACK_DEF(_ccallback){
	// tag, len, data, state
	_config_parse_state_t *st = (_config_parse_state_t*)state;

	// Is this the end of the walk?
	if( data == NULL && tag == TFTLV_CB_TAG_END ) return TFTLV_CB_RET_CONTINUE;

	// If we already have an error, just skip parsing
	// anything else
	if( st->res != _CONFIG_OK ) return TFTLV_CB_RET_CONTINUE;

	switch(tag){
	case TAG_MSGURL:
		if( len < 4 ) goto bad_tag_len;
		else {
			uint16_t port = data[0] | (data[1] << 8);
			uint16_t fl = data[2] | (data[3] << 8);
			if( ((fl & 0xfff) + 4 + 2) > len ) goto bad_tag_len;

			_CONFIG.req_messages.port = port;
			_CONFIG.req_messages.hostname = (char*)&data[4];
			_CONFIG.req_messages.request_pq = (char*)&data[4 + (fl & 0xfff)];
			if( fl & 0x8000 ) _CONFIG.req_messages.flags |= TFN_WEBREQUEST_FLAG_SSL;

			ALOG("CI:TAG: CONFIG: messages host=%s port=%d pq=%s ssl=%d",
				_CONFIG.req_messages.hostname,
				_CONFIG.req_messages.port, _CONFIG.req_messages.request_pq,
				(_CONFIG.req_messages.flags & TFN_WEBREQUEST_FLAG_SSL)?1:0 );

			// TODO: set a flag?
		}
		break;

	case TAG_MINVER:
		if( len == 4 ){
			uint32_t v = data[0] | (data[1] << 8) | (data[2] << 16) | (data[3] << 24);
			if( v > ASVERSION ){
				ALOG("CI:ERR: min ver");
				st->res = _CONFIG_ERR_MINVER;
			}
		}
		else goto bad_tag_len;
		break;

	case TAG_ORG:
		if( len <= ASMA_ORGID_MAX ){
			MEMCPY( _CONFIG.id_org, data, len );
			st->org = 1;
		}
		else goto bad_tag_len;
		break;

	case TAG_GENTS:
		if( len == 4 ){
			uint32_t v = data[0] | (data[1] << 8) | (data[2] << 16) | (data[3] << 24);
			_CONFIG.ts_config = v;
		}
		else goto bad_tag_len;
		break;

	case TAG_FLAGS:
		if( len == 4 ){
			uint32_t v = data[0] | (data[1] << 8) | (data[2] << 16) | (data[3] << 24);
			if( v & 0x01 ) _CONFIG.flag_analytics_coalesce = 0;
			if( v & 0x02 ) _CONFIG.flag_pro_edition = 1;
			if( v & 0x04 ) _CONFIG.flag_disable_errors = 1;
			if( v & 0x08 ) _CONFIG.flag_disable_user2_persist = 1;
			if( v & 0x10 ) _CONFIG.flag_scb_failure_crash = 1;
			if( v & 0x20 ) _CONFIG.flag_disable_background_monitor = 1;
			if( v & 0x40 ) _CONFIG.flag_disable_proxy = 1;
			if( v & 0x80 ) _CONFIG.flag_fdc = 1;
			st->flagged = 1;
		}
		else goto bad_tag_len;
		break;

	case TAG_LIC:
		if( len < sizeof(ASL_License_App_t) ) goto bad_tag_len;
		else {
			ASL_License_App_t *lic = (ASL_License_App_t*)data;
			uint16_t platform = 1 << SYSTEMID;
			if( lic->header.product != ASL_PRODUCT_ASMA || (lic->header.platforms & platform) == 0 )
			{
				// Not for this product or platform
				break;
			}
			if( (sizeof(ASL_License_App_t)+lic->len) != len )
			{
				ALOG("CI:ERR: license spec issue");
				error_report(ERRORBASE_CP+__LINE__,0,0);
				break;
			}

			if( lic->header.expire > 0 ){
				time_t now = time(NULL);
				if( now > lic->header.expire ){
					ALOG("CI:WARN: license expired");
					break;
				}
			}

			if( lic->len == 1 && lic->nom[0] == '.' ){
				ALOG("CI:TAG: NOTE: wildcard license");
				st->licensed = 1;
				break;
			} else {
				if( MEMCMP( _CONFIG.pkg, lic->nom, lic->len ) != 0 ){
					// App name doesn't match
					ALOG("CI:WARN: license/app mismatch");
					break;
				}
	
				// We checked the prefix; now see if license is for specific
				// app or prefix
				if( lic->nom[ lic->len - 1 ] != '.' ){
					// Must be for explicit app name match
					size_t pl = STRLEN(_CONFIG.pkg);
					if( pl != lic->len ){
						// length mismatch; check for ".test"
						if( pl != (lic->len + 5) || 
							MEMCMP(&_CONFIG.pkg[pl-6],".test",5) != 0 ){
							ALOG("CI:WARN: license non-exact match");
							break;
						}
					}
				}

				// If we get here, we are set/licensed
				st->licensed = 1;
				break;
			}
		}
		break;

	case TAG_PINS:
		// We only sanity-check the pin basis here; pin processing is done later
		// Pins are 32 bytes of hash + variable length hostname (at least one char)
		ASSERT( TCL_SHA256_DIGEST_SIZE == 32 );
		if( len < 33 ) goto bad_tag_len;

		// Require a terminating NULL as the last char
		if( data[len-1] != 0 ) goto bad_tag_len;
		break;

	} // switch

	return TFTLV_CB_RET_CONTINUE;

bad_tag_len:
	ALOG("CI:ERR: Bad len (%d) for tag %d", len, tag);
	st->res = _CONFIG_ERR_CORRUPT;
	return TFTLV_CB_RET_STOP;
}



// Walk callback for config keys TLV
TFTLV_CALLBACK_DEF(_cscallback){
	// tag, len, data, state
	_config_sig_state_t *st = (_config_sig_state_t*)state;

	// Is this the end of the walk?
	if( data == NULL && tag == TFTLV_CB_TAG_END ) return TFTLV_CB_RET_CONTINUE;

	// Load in special set flags
	if( tag == TAG_SET_FLAGS && len == 4 ){
		uint32_t v = data[0] | (data[1] << 8) | (data[2] << 16) | (data[3] << 24);

		if(v & 0x01) _CONFIG.flag_nonprod = 1;

		return TFTLV_CB_RET_CONTINUE;
	}

	// // If we are already verified, we can skip further checking
	// if( st->verified > 0 ) return TFTLV_CB_RET_CONTINUE;

#ifdef SIGN_WITH_RSA
	if( tag != TAG_KEY_RSA ) return TFTLV_CB_RET_CONTINUE;
	if( len < 256 ) return TFTLV_CB_RET_CONTINUE;

	// Try this key for use in verification
	st->tried++;
	int err = 0;
	int res = TCL_RSA_Verify( data, len, st->digest, st->sig->rsa, &err );
	ALOG("CI:TAG: CONFIG: tried RSA key res=%d err=%d", res, err);
	if( res == TCL_VERIFY_OK ){
			st->verified++;
			ALOG("CI:TAG: CONFIG: verified with key rsa");
			_CONFIG.key_config = data;
			_CONFIG.key_config_len = len;
			return TFTLV_CB_RET_STOP;
	}
	else if( res != TCL_VERIFY_FAIL ){
		ALOG("CI:ERR: CONFIG: verify rsa res=%d err=%d", res, err);
		error_report(ERRORBASE_CP+__LINE__, err, 0);
	}
#else
	// Make sure it's the right key type & size
	if( tag != TAG_KEY_ECC ) return TFTLV_CB_RET_CONTINUE;
	if( len != TCL_ECC_PUB_SIZE ) return TFTLV_CB_RET_CONTINUE;

	// Try this key for use in verification
	st->tried++;
	int err = 0;
	int res = TCL_ECC_Verify( data, st->digest, st->sig->ecc, &err );
	ALOG("CI:TAG: CONFIG: tried ECC key res=%d err=%d", res, err);
	if( res == TCL_VERIFY_OK ){
			st->verified++;
			ALOG("CI:TAG: CONFIG: verified with key ecc");
			_CONFIG.key_config = data;
			_CONFIG.key_config_len = len;
			return TFTLV_CB_RET_STOP;
	}
	else if( res != TCL_VERIFY_FAIL ){
		ALOG("CI:ERR: CONFIG: verify ecc res=%d err=%d", res, err);
		error_report(ERRORBASE_CP+__LINE__, err, 0);
	}
#endif

	return TFTLV_CB_RET_CONTINUE;
}

int _keys_loaded = 0;

// Callback for TLV signatures (both config keys & config)
TFTLV_SIGCALLBACK_DEF(_scallback){
	// data, data_len, sig, otp

	_config_sig_t *s = (_config_sig_t*)sig;

	// Hash the data
	uint8_t digest[TCL_SHA256_DIGEST_SIZE];
	if( TCL_SHA256( data, data_len, digest ) != 0 ){
		ALOG("CI:ERR: CONFIG: signature digesting");
		return error_report(ERRORBASE_CP+__LINE__, 0, TFTLV_RET_IO);
	}

	if( _keys_loaded == 0 ){
		ALOG("CI:TAG: CONFIG: loading keys TLV");
		// We are loading keys, so verify against our embedded root keys
		int i;

#ifdef SIGN_WITH_RSA
		for( i=0; i<KEYS_RSA_ROOT_CNT; i++){
			int err = 0;
			// TODO: replace 292
			int res = TCL_RSA_Verify( &KEYS_RSA_ROOT[i][0], 292, digest, s->rsa, &err );
			ALOG("CI:TAG: CONFIG: trying rsa key %d, res=%d, err=%d", i, res, err);
			if( res == TCL_VERIFY_OK ){
				ALOG("CI:TAG: CONFIG: verified with key %d rsa", i);
				TFMEMCPY(otp, s->otp, TFTLV_OTP_SIZE);
				_keys_loaded++;
				_CONFIG.key_root = &KEYS_RSA_ROOT[i][0];
				_CONFIG.key_root_len = 292;
				return TFTLV_RET_OK;
			}
		}
#else
		for( i=0; i<KEYS_ECC_ROOT_CNT; i++){
			int err = 0;
			int res = TCL_ECC_Verify( KEYS_ECC_ROOT[i], digest, s->ecc, &err );
			ALOG("CI:TAG: CONFIG: trying ecc key %d, res=%d, err=%d", i, res, err);
			if( res == TCL_VERIFY_OK ){
				ALOG("CI:TAG: CONFIG: verified with key %d ecc", i);
				TFMEMCPY(otp, s->otp, TFTLV_OTP_SIZE);
				_keys_loaded++;
				_CONFIG.key_root = &KEYS_ECC_ROOT[i][0];
				_CONFIG.key_root_len = 64;
				return TFTLV_RET_OK;
			}
		}
#endif
	} else {
		// We have loaded keys, so verify via a walk
		ALOG("CI:TAG: CONFIG: loading data TLV");
		_config_sig_state_t st;
		MEMSET(&st, 0, sizeof(st));
		st.sig = s;
		st.digest = digest;

		int res = TFTLV_Walk_Mem( &_CONFIG.tlv_keys, &_cscallback, &st );
		if( res != TFTLV_RET_OK ){
			// Main return types would be _FORMAT and _INTEGRITY
			return error_report(ERRORBASE_CP+__LINE__, res, res);
		}
		if( st.tried > 0 && st.verified > 0 ){
			// TODO
			TFMEMCPY(otp, s->otp, TFTLV_OTP_SIZE);
			return TFTLV_RET_OK;
		}
	}

	ALOG("CI:ERR: CONFIG: not verified");
	return TFTLV_RET_INTEGRITY;
}

__attribute__((always_inline))
static inline int config_parse( uint8_t *data, uint32_t datalen ) 
{
	ASSERT(TFTLV_SIG_SIZE == sizeof(_config_sig_t));
	ASSERT(data);

	int found = 0, record;
	CHECK_HOOK(TFTLV_Init_MemFromSignedMem, found, record);
	CHECK_HOOK(TFTLV_Walk_Mem, found, record);
	CHECK_HOOK(_scallback, found, record);
	CHECK_HOOK(_cscallback, found, record);
	CHECK_HOOK(_ccallback, found, record);
#ifdef SIGN_WITH_RSA
	CHECK_HOOK(TCL_RSA_Verify, found, record);
#else
	CHECK_HOOK(TCL_ECC_Verify, found, record);
#endif
	CHECK_HOOK(TCL_SHA256, found, record);
	REPORT_HOOKING(found, record);

	//
	// Format: <uint32_t magic> + <uint32_t size> + <tlv1 of size> + <tlv2>
	// - TLV1 is signed by a root key, and only contains more online keys
	// - TLV2 is the actual config file, signed by an authorized online key
	//
	uint32_t *u32 = (uint32_t*)data;
	if( datalen < 8 || (*u32) != MAGIC ){
		return error_report(ERRORBASE_CP+__LINE__, 0, _CONFIG_ERR_CORRUPT);
	}
	u32++;
	uint32_t tlv1_size = *u32;
	if( datalen < sizeof(uint32_t) || (tlv1_size + 4) >= (datalen - 4) ){
		return error_report(ERRORBASE_CP+__LINE__, 0, _CONFIG_ERR_CORRUPT);
	}

	//
	// Process TLV1
	//

	// Load & sig check the config key data
	ALOG("CI:TAG: checking config keys with size=%d", tlv1_size);
	uint8_t res = TFTLV_Init_MemFromSignedMem( &_CONFIG.tlv_keys, &data[8], tlv1_size, &_scallback );
	if( res == TFTLV_RET_INTEGRITY ){
		ALOG("CI:ERR: sig verification of config keys");
		return error_report(ERRORBASE_CP+__LINE__,0,_CONFIG_ERR_SIG);
	}
	else if( res != TFTLV_RET_OK ){
		ALOG("CI:ERR: data validity of config keys: %d", res);
		return error_report(ERRORBASE_CP+__LINE__, res, _CONFIG_ERR_CORRUPT);
	}
	ALOG("CI:TAG: config keys loaded");

	// We will walk the config key data as part of the config data (tlv2) sig callback


	//
	// Process TLV2
	//

	// Load & sig check the config data
	res = TFTLV_Init_MemFromSignedMem( &_CONFIG.tlv_config, &data[tlv1_size+8], datalen - tlv1_size - 8, &_scallback );
	if( res == TFTLV_RET_INTEGRITY ){
		ALOG("CI:ERR: sig verification of config");
		return error_report(ERRORBASE_CP+__LINE__,0,_CONFIG_ERR_SIG);
	}
	else if( res != TFTLV_RET_OK ){
		ALOG("CI:ERR: data validity of config: %d", res);
		return error_report(ERRORBASE_CP+__LINE__, res, _CONFIG_ERR_CORRUPT);
	}

	// Set up our initial state
	_config_parse_state_t state;
	MEMSET(&state, 0, sizeof(state));
	state.res = _CONFIG_OK;

	// Walk the memory, checking and loading in data as it goes
	res = TFTLV_Walk_Mem( &_CONFIG.tlv_config, &_ccallback, &state );
	if( res != TFTLV_RET_OK ){
		return error_report(ERRORBASE_CP+__LINE__, res, 
			res == TFTLV_RET_INTEGRITY ? _CONFIG_ERR_INTEGRITY : _CONFIG_ERR_CORRUPT);
	}

	// Check the callback's reported state
	if( state.res != _CONFIG_OK ){
		return error_report(ERRORBASE_CP+__LINE__, state.res, state.res);
	}

	// Make sure we are licensed
	if( state.licensed == 0 ){
		ALOG("CI:ERR: unlicensed");
		return error_report(ERRORBASE_CP+__LINE__,0,_CONFIG_ERR_LICENSE);
	}

	// All set
	return _CONFIG_OK;

}
