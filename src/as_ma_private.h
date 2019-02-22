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

#ifndef _AS_MA_PRIVATE_H_
#define _AS_MA_PRIVATE_H_

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#include "as_cti.h"
#include "config.h"

#include "as_ma_platform.h"

#define ASDEFS_SECTION_FILES            1
#define ASDEFS_SECTION_APPS             2
#define ASDEFS_SECTION_SYMBOLS          3
#define ASDEFS_SECTION_LIBS             4
#define ASDEFS_SECTION_SIGS             5
#define ASDEFS_SECTION_ENV             6
#define ASDEFS_SECTION_PROPS             7
#define ASDEFS_SECTION_HOOKS             8
#define ASDEFS_SECTION_PROXY             9
#define ASDEFS_SECTION_APPROVEDDYLIBS             10

#define OBINIT_OK		0
#define OBINIT_DEFSFORMAT	-1
#define OBINIT_DEFSINTEGRITY	-2

#define FDC_LIBRARY		1
#define FDC_SYMBOL		2
#define FDC_RTSYMBOL		3
#define FDC_SYMLOC		4

int bootstrap( const char appnom[ASMA_PKG_MAX], const char appver[ASMA_PKGVER_MAX],
        const char *rpath, const char *cpath, const uint8_t sysid[ASMA_SYSID_MAX], 
	void(*callback)(int,int,ASCTI_Item_t*), uint32_t flags_local );

int bootstrap_ex( const char appnom[ASMA_PKG_MAX], const char appver[ASMA_PKGVER_MAX],
        const char *rpath, const char *cpath, const uint8_t sysid[ASMA_SYSID_MAX], 
	void(*callback)(int,int,ASCTI_Item_t*), uint32_t flags_local,
	uint8_t *config, uint32_t config_sz);

#define _BOOTSTRAP_OK		1
#define _BOOTSTRAP_SETUP	-1
#define _BOOTSTRAP_INTEGRITY	-2
#define _BOOTSTRAP_LICENSE	-3
//#define _BOOTSTRAP_ARMONX86	-4
#define _BOOTSTRAP_DEFS		-5
#define _BOOTSTRAP_ALREADYINIT	-6
#define _BOOTSTRAP_OLDCONFIG	-7

int customer_message( uint32_t id, const char *data );
int customer_identity( const char *data );
void customer_reachability();
void customer_login_status( int status );

#define _CONFIG_OK		1
#define _CONFIG_ERR_CORRUPT	-1
#define _CONFIG_ERR_LICENSE	-2
#define _CONFIG_ERR_SIG		-3
#define _CONFIG_ERR_MINVER	-4
#define _CONFIG_ERR_OLDFORMAT	-5
#define _CONFIG_ERR_INTEGRITY	-6

int messages_init();
int message_add( ASCTI_Item_t *item );
void messages_flush();

void ctiitem_setup_app( ASCTI_Item_t *item );
void ctiitem_setup_sys( ASCTI_Item_t *item );

int watchers_init();

void ssl_violation( char *hostname, uint8_t *cert, uint32_t cert_len );

int analytics_coalesce_check( uint64_t cache[], uint8_t cache_count, uint32_t flags, uint16_t id );
void analytics_coalesce_add( uint64_t cache[], uint8_t cache_count, uint8_t *cache_index, uint32_t flags, uint16_t id );
void analytics_posture_contribution( ASCTI_Item_t *item );
uint32_t analytics_get_posture();

#define A_FLAG_COMPLETED	0x0001
#define A_FLAG_EMULATOR		0x0002
#define A_FLAG_ROOTED		0x0004
#define A_FLAG_NEVER		0x0008
#define A_FLAG_NONPROD		0x0010
#define A_FLAG_HACKTOOL		0x0020
#define A_FLAG_ALWAYS		0x0040
#define A_FLAG_SEFSOF		0x0080
#define A_FLAG_DEBUGGER		0x0100
#define A_FLAG_TAMPERING	0x0200
#define A_FLAG_NETWORK		0x0400
#define A_FLAG_MALWARE		0x0800
#define A_FLAG_GAMETOOL		0x1000
#define A_FLAG_DEVBUILD		0x2000
#define A_FLAG_DEVTOOL		0x4000

int error_report( uint32_t err, uint32_t err2, int ret );
int proxy_setup( TFN_WebRequest_t *req, int report );

void stealth_callbacks();
void stealth_callbacks_conclude();

uint32_t heartbeat(uint32_t inp);
void heartbeat_internal();

void mitm_check();

char *_decode( uint32_t sz, const uint32_t *in, uint32_t *work );

int guarded_init();
int guarded_uint32_get(int slot, uint32_t *result);
int guarded_uint32_set(int slot, uint32_t value);

#define GUARDED_SLOT_MONLEVEL	63
#define GUARDED_SLOT_POSTURE	62

#ifdef __cplusplus
}
#endif

#endif // _AS_MA_H_
