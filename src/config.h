#ifndef _CONFIG_H_
#define _CONFIG_H_

#include <stdint.h>
#include <pthread.h>

#define MEMCPY(...)	TFMEMCPY(__VA_ARGS__)

#include PLATFORM_H

#include "tf_defs.h"
//#include "tf_qf.h"
#include "tf_netsec.h"
#include "tf_crypto.h"
#include "tf_cal.h"
#include "tf_tlv.h"

#include "as_cti.h"

#define ASMA_PATH_MAX		512
#define ASMA_PKG_MAX		128
#define ASMA_PKGVER_MAX		32
#define ASMA_USER2_MAX		128
#define ASMA_ORGID_MAX		32
#define ASMA_SYSID_MAX		32
#define ASMA_PINS_COUNT_MAX	16
#define ASMA_SCB_MAX		128
#define ASMA_ERRFP_MAX		128

#define _F_DEFS_AS	"as.def\x00"
#define _F_DEFS_CUST	"cust.defs\x00"
#define _F_CONF_AS	"as.conf\x00"
#define _F_MSG_FQA	".q\x00"

#define _P_ID1		"i1"
#define _P_ID2		"i2"
#define _P_LASTSTART	"ls"
#define _P_DEVICEID	"di"

#define _SUBTEST_INTERNAL_INTEGRITY	1
#define _SUBTEST_INTERNAL_DEFSIG	2
#define _SUBTEST_INTERNAL_CONFIGSIG	3
#define _SUBTEST_INTERNAL_QFSIG		4
#define _SUBTEST_INTERNAL_WATCHDOG	5
#define _SUBTEST_INTERNAL_MONITOR	6
#define _SUBTEST_INTERNAL_CONFIGINTEGRITY	7
#define _SUBTEST_INTERNAL_PERSISTINTEGRITY	8
#define _SUBTEST_INTERNAL_HOOKCHECK	9
#define _SUBTEST_INTERNAL_GUARDED	10

#define _LASTSTART_VERSION		4

// Checksums for de-duplication
typedef struct {
	uint32_t version;
	uint32_t hardware;
	uint32_t firmware;
	uint32_t kernel;
	uint32_t os;
	uint32_t ts_config;
	uint32_t v_lib;
	uint32_t v_defs1;
	uint32_t v_defs2;
	uint32_t v_vc;
	uint32_t signer1;	// IOS: exe / Android:
	uint32_t signer2;	// IOS: embprov / Android:
	uint32_t measure1;	// IOS: exe file / Android: so
	uint32_t measure2;	// IOS: mach headers / Android:
	uint32_t measure3;	// IOS: text image / Android: text image
	uint32_t measure4;	// IOS: / Android: APK
	uint32_t ts;
} ASMA_LastStart_t;


typedef struct {
	uint8_t rpath[ASMA_PATH_MAX];	// Resource path (read-only)
	uint8_t cpath[ASMA_PATH_MAX]; // Cache path (read-write)

	// The config TLVs
	TFTLV_Mem_t tlv_keys;
	TFTLV_Mem_t tlv_config;

	// The keys in use (for signing the TLVs) (V2)
	uint8_t *key_root, *key_config;
	uint32_t key_root_len, key_config_len;

	// Identity stuff
	size_t pkg_sz;
	char pkg[ASMA_PKG_MAX];
	char pkgver[ASMA_PKGVER_MAX];

	uint8_t id_org[ASMA_ORGID_MAX];
	uint8_t id_sys1[ASMA_SYSID_MAX];
	char user2[ASMA_USER2_MAX];

	// Our defs
	TF_Defs_t defs_as;

	ASCTI_Config_t cti_config;
	TFN_WebRequest_t req_messages;

	TFTLV_Mem_t mqA;
	TFTLV_File_t fqA;
	int mqA_lock, fqA_lock;
	//uint8_t qf_key[TFTLV_KEY_SIZE];

	// Messaging callback
	void (*msg_callback)(int,int,ASCTI_Item_t*);

	// Stealth callbacks
	// TODO: V2 cleanup:
	uint8_t scb1[ ASMA_SCB_MAX ];
	uint8_t scb2[ ASMA_SCB_MAX ];
	uint32_t scb_in;
	uint32_t scb_out;

	// Some tracking state (V2)
	uint32_t track_debug;
	

	// HPKP Pins
	// TODO: V2 cleanup:
	uint8_t hpkp_pins[ASMA_PINS_COUNT_MAX][ TCL_SHA256_DIGEST_SIZE ];
	uint32_t hpkp_pins_count;

	// Small fingerprint of device/OS info used for error reporting
	uint8_t err_fp[ASMA_ERRFP_MAX];

	// Timestamps of things
	uint32_t ts_config;

	// Flags mis-mash
	uint32_t flag_bootstrapped : 1;

	uint32_t flag_pro_edition : 1;
	uint32_t flag_configured : 1;
	uint32_t flag_cb : 1;
	uint32_t flag_messaging : 1;
	uint32_t flag_messaging_network : 1;
	uint32_t flag_has_user2 : 1;
	uint32_t flag_analytics_coalesce : 1;
	uint32_t flag_disable_errors : 1;
	uint32_t flag_disable_user2_persist : 1;
	uint32_t flag_scb_failure_crash : 1;
	uint32_t flag_debugger_go : 1;
	uint32_t flag_disable_background_monitor : 1;
	uint32_t flag_startup_completed : 1;
	uint32_t flag_elevated_monitoring : 1;

	uint32_t flag_disable_proxy : 1; // V2
	uint32_t flag_fdc : 1; // V2
	uint32_t flag_nonprod : 1; // V2

	// Laststart info
	ASMA_LastStart_t laststart;

} ASMA_Config_t;

extern uint8_t _KEYS[][TFC_ED25519_PK_SIZE];
#define KEYS_RSA_ROOT_CNT 1
extern uint8_t KEYS_RSA_ROOT[KEYS_RSA_ROOT_CNT][292];
#define KEYS_ECC_ROOT_CNT 1
extern uint8_t KEYS_ECC_ROOT[KEYS_ECC_ROOT_CNT][64];

extern ASMA_Config_t _CONFIG;
extern pthread_mutex_t _CONFIG_LOCK;

#endif
