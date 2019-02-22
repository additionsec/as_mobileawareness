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

#ifndef _OB_STARTUP_INLINE_C_
#define _OB_STARTUP_INLINE_C_


#include <CoreFoundation/CoreFoundation.h>
#include <objc/runtime.h>
#include <objc/message.h>

#include <sys/types.h>
#include <sys/sysctl.h>
#include <unistd.h>
#include <sys/utsname.h>
#include <sys/syscall.h>
#include <sys/param.h>
#include <sys/mount.h>
#include <stdio.h>
#include <errno.h>

#include <dlfcn.h>
#include <mach-o/dyld.h>
#include <mach-o/dyld_images.h>

#include "as_ma_private.h"
#include "as_ma_platform.h"
#include "ascti_tests.h"
#include "as_defs_flags.h"

#include "tf_cal.h"

#define ERRORBASE_OBSS 53000

#include "observations_debugger.inline.c"
#include "observations_symbols.inline.c"
#include "observations_files.inline.c"
#include "observations_embprov.inline.c"
#include "observations_hooks.inline.c"
#include "observations_env.inline.c"

extern char **environ;

#define WORK_MAX	8

static const uint32_t UIDEVICE[] = {0x37e99cb9,0x9fb0691,0x5e86f9cc,}; // "UIDevice"
static const uint32_t CURRENTDEVICE[] = {0x20dfa08f,0x3fda3db4,0xbceb48c,0x58b74fb5,}; // "currentDevice"
static const uint32_t SYSTEMVERSION[] = {0x26deac9f,0x18f932a4,0x20edbe8b,0x739445b9,}; // "systemVersion"
static const uint32_t SECURITYMACPROC_ENFORCE[] = {0x27ceb09f,0x5cb2ab3,0x31d7b8c0,0xddc33b2,0x2cdc8b8a,0x4cf07b6,0x43a2e88a,}; // "security.mac.proc_enforce"
static const uint32_t SECURITYMACVNODE_ENFORCE[] = {0x27ceb09f,0x5cb2ab3,0x31d7b8c0,0xdc035b2,0x27fab78d,0x1ef432b9,0x5999b883,}; // "security.mac.vnode_enforce"

#define _S(nom) _decode((sizeof(nom)/4)-1,nom,work)


#define ITEMSET(t, typ, st) do { \
	MEMSET( &item, 0, sizeof(item) );\
	item.test = t; \
	item.subtest = st; \
	item.type = typ; \
	} while(0)

#define ITEMDATA1(d1typ,d1len,d1) do { \
	item.data1_type = d1typ; \
	item.data1_len = d1len; \
	item.data1 = d1; \
	} while(0)


#include "seed.h"


void observations_startup( int flags )
{
	uint32_t work[WORK_MAX]; // For string decoding
	int r;

        ASCTI_Item_t item;
	uint32_t u32, u32x;
	struct utsname utsname;
	size_t sz;

	uint32_t seed = SEED_START;
	while(1){
	 uint32_t s = _SEED_NEXT(seed);
	 switch(s){

	case SEED_1:
	{
		//
		// Log application version info
		//
		ctiitem_setup_app( &item );
		item.test = CTI_TEST_APPLICATIONINFO;
		ITEMDATA1( ASCTI_DT_VERSTR, STRLEN(_CONFIG.pkgver), _CONFIG.pkgver );
		message_add( &item );
	}
	break;

	case SEED_2:
	{
#if TARGET_IPHONE_SIMULATOR
		// We don't test hooks on simulator
#else
		// Check for hooks
		observations_hooks(0, 1);
#endif
	}
	break;

	case SEED_3:
	{
		MEMSET( &utsname, 0, sizeof(utsname) );
		uname(&utsname); // NOTE: if this fails, the strings are NULL/empty

		// This produces "9.0.1", etc.
		// NOT-MVP-TODO: is there a non-objc way to get the OS version?
       	 	id currdev_ = objc_msgSend((id)objc_getClass(_S(UIDEVICE)), sel_getUid(_S(CURRENTDEVICE)));
       	 	if( currdev_ != NULL ){
			char sysver[16] = {0};
        		CFStringRef sysver_ = (CFStringRef)objc_msgSend(currdev_, sel_getUid(_S(SYSTEMVERSION)));
			if( sysver_ != NULL ){
				CFStringGetCString(sysver_, sysver, sizeof(sysver), kCFStringEncodingUTF8);

				// Add the sysver to the err_fp; room was reserved, above
				size_t s = STRLEN(sysver);
				MEMCPY( &_CONFIG.err_fp[STRLEN((const char*)_CONFIG.err_fp)], sysver, s );

				u32 = TCL_CRC32( (uint8_t*)sysver, s );

				ctiitem_setup_sys( &item );
				item.test = CTI_TEST_SYSTEMOSINFO;
				ITEMDATA1( ASCTI_DT_VERSTR, s, sysver );

				if( _CONFIG.laststart.os == (u32) && _CONFIG.flag_analytics_coalesce > 0 )
					item.flag_no_send = 1;	
				else
					_CONFIG.laststart.os = u32;

				message_add( &item );

				// TODO CFRelease(sysver_);
			}

			// TODO CFRelease(currdev_);
		}
	}
	break;

	case SEED_4:
	{
		// This is machine, like "iPhone7,2"
		if( utsname.machine[0] != 0 ){
			size_t s = STRLEN(utsname.machine);

			// Set the machine name to the err_fp, if it fits (leave room for sysver, below)
			if( s < ASMA_ERRFP_MAX - 18 ){
				MEMCPY( _CONFIG.err_fp, utsname.machine, s );
				_CONFIG.err_fp[s] = '/';
			}

			u32 = TCL_CRC32( (uint8_t*)utsname.machine, s );

			ctiitem_setup_sys( &item );
			item.test = CTI_TEST_SYSTEMHARDWAREINFO;
			ITEMDATA1( ASCTI_DT_MODEL, s, utsname.machine );

			if( _CONFIG.laststart.hardware == (u32) && _CONFIG.flag_analytics_coalesce > 0 )
				item.flag_no_send = 1;
			else {
				if( (uint32_t)(_CONFIG.laststart.hardware) != (uint32_t)(u32) &&
					_CONFIG.laststart.hardware != 0 )
				{
					// We dont' really expect the hardware identifier to change, ever.  So
					// send us an indicator if it does
					ALOG("CI:WARN: laststart.hardware went from %08x to %08x",
						_CONFIG.laststart.hardware, u32);
					error_report(ERRORBASE_OBSS+__LINE__,0,0);
				}
				_CONFIG.laststart.hardware = u32;
			}
	
			message_add( &item );
		}
	}
	break;

	case SEED_5:
	{
		if( _CONFIG.flag_pro_edition && utsname.version[0] != 0 ){
			// This is the kernel version string, e.g.:
			//"Darwin Kernel Version 15.0.0: Wed Dec  9 22:19:37 PST 2015; root:xnu-3248.31.3~2/RELEASE_ARM64_T7000"

			size_t s = STRLEN(utsname.version);

			u32 = TCL_CRC32( (uint8_t*)utsname.version, s );

			ctiitem_setup_sys( &item );
			item.test = CTI_TEST_SYSTEMFIRMWAREINFO;
			ITEMDATA1( ASCTI_DT_VERSTR, s, utsname.version );

			if( _CONFIG.laststart.firmware == (u32) && _CONFIG.flag_analytics_coalesce > 0 )
				item.flag_no_send = 1;
			else
				_CONFIG.laststart.firmware = u32;

			message_add( &item );
		}
	}
	break;

#if TARGET_IPHONE_SIMULATOR
	case SEED_6:
	{
		// If it's the simulator, then overwrite the err_fp
		_CONFIG.err_fp[0] = 'S';
		_CONFIG.err_fp[1] = 'I';
		_CONFIG.err_fp[2] = 'M';
		_CONFIG.err_fp[3] = 0;

       	 	// Log simulator message
		#define SIMMSG "Simulator build"
		ctiitem_setup_sys( &item );
		item.test = CTI_TEST_SYNTHETICSYSTEMARTIFACT;
		ITEMDATA1( ASCTI_DT_STRING, STRLEN(SIMMSG), SIMMSG );
		message_add( &item );
	}
	return;

#else
	///////////////////////
        // Normal device
	///////////////////////

	case SEED_6:
	{
		//
		// Check the environment
		//
		observations_env();
	}
	break;

	case SEED_7:
	{
		//
		// Do a debugger check
		//
		observations_debugger(0, &_CONFIG.track_debug);
	}
	break;

	case SEED_8:
	{
		//
		// Do a dylibs check
		//
		observations_dylibs();
	}
	break;

	case SEED_9:
	{
		// Check if root FS is mounted RO or RW
		struct statfs stf;
		if( STATFS("/", &stf) == 0 ){
			if( (stf.f_flags & MNT_RDONLY) == 0 ){
				ALOG("CI:TAG: MOUNTRW");
				ctiitem_setup_sys( &item );
				item.test = CTI_TEST_SECURITYEXPECTATIONFAILURE;
				item.subtest = 42;
				item.data3 = ERRORBASE_OBSS+__LINE__;
				item.data3_type = ASCTI_DT_VRID;
				message_add( &item );
			}
		} else {
			ALOG("CI:ERR: statfs");
				error_report( ERRORBASE_OBSS+__LINE__, errno, -3);
		}
	}
	break;

	case SEED_10:
	{
		// Check our app is running uid/gid 501 ("mobile")
		if( getuid() != 501 || geteuid() != 501 || getgid() != 501 ){
			ALOG("CI:TAG: CTI: bad mobile ids");
			ctiitem_setup_app( &item );
			item.test = CTI_TEST_SECURITYEXPECTATIONFAILURE;
			item.subtest = 43;
			item.data3 = ERRORBASE_OBSS+__LINE__;
			item.data3_type = ASCTI_DT_VRID;
			message_add( &item );
		}
	}
	break;

	case SEED_11:
	{
		observations_embedded_provisioning();
	}
	break;

	case SEED_12:
	{
		// Check if enforcements are on (proc)
		u32x = 0;
		sz = sizeof(u32x);
		// NOT-MVP-TODO: convert sysctlbyname to sysctl with the OID
		if( sysctlbyname(_S(SECURITYMACPROC_ENFORCE), &u32x, &sz, NULL, 0 ) == 0 && u32x == 0 ){
			ALOG("CI:TAG: CTI: proc enforce off");
			ctiitem_setup_sys( &item );
			item.test = CTI_TEST_SECURITYEXPECTATIONFAILURE;
			item.subtest = 44;
			ITEMDATA1( ASCTI_DT_PROPERTYNAME, STRLEN((char*)work), (char*)work );
			item.data3 = ERRORBASE_OBSS+__LINE__;
			item.data3_type = ASCTI_DT_VRID;
			message_add( &item );
		}
	}
	break;

	case SEED_13:
	{
		// Check if enforcements are on (vnode)
		u32x = 0;
		sz = sizeof(u32x);
		// NOT-MVP-TODO: convert sysctlbyname to sysctl with the OID
		if( sysctlbyname(_S(SECURITYMACVNODE_ENFORCE), &u32x, &sz, NULL, 0 ) == 0 && u32x == 0 ){
			ALOG("CI:TAG: CTI: vnode enforce off");
			ctiitem_setup_sys( &item );
			item.test = CTI_TEST_SECURITYEXPECTATIONFAILURE;
			item.subtest = 45;
			ITEMDATA1( ASCTI_DT_STRING, STRLEN((char*)work), (char*)work );
			item.data3 = ERRORBASE_OBSS+__LINE__;
			item.data3_type = ASCTI_DT_VRID;
			message_add( &item );
		}
	}
	break;

	case SEED_14:
	{
		observations_symbols(ASDEFS_SECTION_SYMBOLS);
	}
	break;

	case SEED_15:
	{
        	observations_files(ASDEFS_SECTION_FILES);
	}
	break;

	case SEED_16:
	{
		// Check codesign
		//
		// TESTING: jailbroken = 0x6001005
		// TESTING: nonjailbroken = 0x2001305
		//
		// https://github.com/axelexic/CSOps/blob/master/CSOps/CSOps.c
		// https://github.com/axelexic/CSOps/blob/master/CSOps/codesign.h
		// http://www.opensource.apple.com/source/xnu/xnu-2422.1.72/bsd/sys/codesign.h
#define	CS_OPS_STATUS		0	/* return status */
#define	CS_VALID		0x0000001	/* dynamically valid */
#define CS_GET_TASK_ALLOW	0x0000004	/* has get-task-allow entitlement (debug) */
#define CS_HARD			0x0000100	/* don't load invalid pages */
#define CS_KILL			0x0000200	/* kill process if it becomes invalid */
#define CS_ENFORCEMENT		0x0001000	/* require enforcement */
		u32x = 0;
		//r = SYSCALL(SYS_csops, 0/*pid*/, CS_OPS_STATUS, &u32x, sizeof(u32x) );
		r = CSOPS( 0/*pid*/, CS_OPS_STATUS, &u32x, sizeof(u32x) );
		if( r == 0 ) {
			ALOG("CI:TAG: CSFLAGS: 0x%x", u32x);
#define COMBO	(CS_VALID|CS_HARD|CS_KILL|CS_ENFORCEMENT)
			if( (u32x & COMBO) != COMBO ){
				ALOG("CI:TAG: CODESIGNING DISABLED");
				ctiitem_setup_app( &item );
				item.test = CTI_TEST_SECURITYEXPECTATIONFAILURE;
				item.subtest = 46;
				item.data3 = ERRORBASE_OBSS+__LINE__;
				item.data3_type = ASCTI_DT_VRID;
				message_add( &item );
			}
			if( u32x & CS_GET_TASK_ALLOW ){
				ALOG("CI:TAG: HAS GETTASKALLOW ENTITLEMENT");
				ctiitem_setup_app( &item );
				item.test = CTI_TEST_OPENAPPLICATIONLOCALATTACKVECTOR;
				item.subtest = 47;
				message_add( &item );
			}
		} else { 
			ALOG("CI:ERR: csops"); 
			error_report(ERRORBASE_OBSS+__LINE__, errno, -4);
			// NOT-MVP-TODO: is this an operational failure/app tampering/SEF?
		}
	}
	break;

	case SEED_17:
	{
		return;
	}
	
#endif // simulator

	default:
	{
                ALOG("CI:ERR: ran off switch");
                ctiitem_setup_app( &item );
                item.test = CTI_TEST_APPLICATIONTAMPERINGDETECTED;
                item.subtest = _SUBTEST_INTERNAL_INTEGRITY;
                item.data3_type = ASCTI_DT_VRID;
                item.data3 = ERRORBASE_OBSS+__LINE__;
                message_add( &item );
                return;
	}

	  } // switch
	} // while
}


#endif
