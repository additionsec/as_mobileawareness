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
#include <sys/mman.h>
#include <errno.h>

#include "as_mobileawareness.h"
#include "as_ma_platform.h"
#include "as_ma_private.h"
#include "as_cti.h"
#include "config.h"

#include "tf_cal.h"

struct _platform_config _PLATFORM_CONFIG;

#define ERRORBASE 24000

#define WORK_MAX 6
static const uint32_t NETHOSTNAME[] = {0x7cd9b082,0x53db2cb4,0x61cbb287,0x32b249db,}; // "net.hostname"
static const uint32_t ROSERIALNO[] = {0x2183ba9e,0x1b9b3ba5,0x4c89aa94,}; // "ro.serialno"
static const uint32_t RILSERIALNUMBER[] = {0x7cc1bc9e,0x4ec22ab3,0x6cd1b98f,0x4dcd20be,0x2a8c7e5,}; // "ril.serialnumber"

#define _S(nom) _decode((sizeof(nom)/4)-1,nom,work)


static void(*_callback)(int,int,uint8_t*,uint32_t,uint8_t*,uint32_t) = NULL;
static void _callback_bridge( int a, int b, ASCTI_Item_t *item )
{
	if( item == NULL || _callback == NULL ) return;
	_callback( a, b, (uint8_t*)item->data1, item->data1_len, (uint8_t*)item->data2, item->data2_len );
}

int AS_Initialize( JNIEnv *env, const uint8_t uuid[32], 
	const uint8_t *config, uint32_t config_len,
	void(*callback)(int,int,uint8_t*,uint32_t,uint8_t*,uint32_t) )
{
	if( uuid == NULL || config == NULL ) return AS_INIT_ERR_GENERAL;
	if( _CONFIG.flag_bootstrapped == 1 ) return AS_INIT_ERR_ALREADYINIT;

	// Config must be writable, so let's copy it over to anon memory
	uint8_t *config_mem = (uint8_t*)MMAP(NULL, config_len, PROT_READ|PROT_WRITE, MAP_ANON|MAP_PRIVATE, -1, 0);
	if( config_mem == MAP_FAILED )
		return error_report(ERRORBASE+__LINE__,errno,AS_INIT_ERR_GENERAL);
	MEMCPY( config_mem, config, config_len );

	// Set up a callback bridge
	void (*cb)(int,int,ASCTI_Item_t*) = NULL;
	if( callback != NULL ){
		_callback = callback;
		cb = _callback_bridge;
	}

	// Do our pre-bootstrap, which passes along to bootstrap
	int ret = bootstrap_pre( env, uuid, config_mem, config_len, cb );
	MUNMAP(config_mem, config_len);

	// Translate the result
	if( ret == _BOOTSTRAP_INTEGRITY ) return AS_INIT_ERR_INTEGRITY;
	else if( ret == _BOOTSTRAP_LICENSE ) return AS_INIT_ERR_LICENSE;
	else if( ret != _BOOTSTRAP_OK ) return AS_INIT_ERR_GENERAL;
	return AS_INIT_SUCCESS;
}

#ifndef GAMEPROTECTLITE

#ifdef UNITY
__attribute__((visibility("default")))
#endif
int AS_Register_Identity( const char *identity )
{
	if( identity == NULL || _CONFIG.flag_bootstrapped == 0 ) return AS_ERR_GENERAL;
	return customer_identity( identity );
}

#ifdef UNITY
__attribute__((visibility("default")))
#endif
int AS_Send_Message( uint32_t id, const char *data )
{
	if( data == NULL || _CONFIG.flag_bootstrapped == 0 ) return AS_ERR_GENERAL;
	return customer_message( id, data );
}

#ifdef UNITY
__attribute__((visibility("default")))
#endif
void AS_Login_Status( int status )
{
	if( _CONFIG.flag_bootstrapped == 0 ) return;
	customer_login_status( status );
}

#ifdef UNITY
__attribute__((visibility("default")))
#endif
void AS_Network_Reachability()
{
	if( _CONFIG.flag_bootstrapped == 0 ) return;
	customer_reachability();
}

#ifdef UNITY
__attribute__((visibility("default")))
#endif
long AS_Heartbeat(long i)
{
	return heartbeat(i);
}

#endif // GAMEPROTECTLITE


#ifdef UNITY
__attribute__((visibility("default")))
#endif
uint32_t AS_Version()
{
	return ASVERSION;
}


#ifdef UNITY
__attribute__((visibility("default")))
#endif
uint32_t AS_Security_Posture()
{
	heartbeat_internal();
	return analytics_get_posture();
}

int AS_UUID_Default_Serial( uint8_t uuid[32] )
{
	if( uuid == NULL ) return AS_ERR_GENERAL;

	char buf[PROP_VALUE_MAX * 3];
	MEMSET( buf, 0, sizeof(buf));
	char *v1 = buf;
	char *v2 = &buf[PROP_VALUE_MAX];
	char *v3 = &buf[PROP_VALUE_MAX * 2];

	uint32_t work[WORK_MAX];

	// NOTE: any of these may not exist/fail; as part
	// of our scheme, if they don't exist, the prior
	// memset just retains the all-zeros value
	int e = 0;
	e += property_get(_S(NETHOSTNAME), v1);
	e += property_get(_S(ROSERIALNO), v2);
	e += property_get(_S(RILSERIALNUMBER), v3);

	TCL_SHA256( (uint8_t*)buf, sizeof(buf), uuid );

	// if e == 0, it means we got no entropy and the uuid
	// is going to basically be hash of all zeros.  But
	// we still return it anyways, so the hash is valid
	// in case the caller ignores the return value.
	if( e == 0 ) return AS_ERR_GENERAL;
	return AS_SUCCESS;
}
