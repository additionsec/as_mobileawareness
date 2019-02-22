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
#include <time.h>
#include <stdlib.h>
#include <sys/inotify.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>
#include <sched.h>
#include <poll.h>
#include <dlfcn.h>

#include "as_ma_platform.h"
#include "as_ma_private.h"
#include "ascti_tests.h"
#include "as_cti.h"
#include "seed.h"

#include "observations/checkhook.h"

#define INOTIFY_MERGE_SECONDS_NORMAL 	30
#define INOTIFY_MERGE_SECONDS_ELEVATED 	10
#define INOTIFY_MERGE_SECONDS_CONFIRMED	3

#define INOTIFY_CACHE_CLEAR		(60 * 15)
#define INOTIFY_FD_SQUELCH		1000

#define WATCHDOG_MIN_COUNT 	5
#define WAIT_SECONDS		4

#define RECHECK_INTERVAL        6

#define ERRORBASE 12000



#ifdef GAMEPROTECTLITE

int watchers_init()
{
	return 0;
}

#else

#include "observations_debugger.inline.c"
#include "observations_hooks.inline.c"
//#include "observations_libs.inline.c"


#define WORK_MAX 8

static const uint32_t SYSTEMLIBLIBCSO[] = {0x21d4a6c3,0x55c830e9,0x2dd7a6d8,0x1dcc34e8,0x52c6a09d,}; // "/system/lib/libc.so"
static const uint32_t SYSTEMLIB64LIBCSO[] = {0x21d4a6c3,0x55c830e9,0x34d7a6d8,0xec272b0,0x3289f689,0x79e815bc,}; // "/system/lib64/libc.so"
static const uint32_t SYSTEMBINAPP_PROCESS[] = {0x21d4a6c3,0x55c830e9,0x2ddba6d6,0x21d22deb,0xdd8b8c0,0x46ca28ff,}; // "/system/bin/app_process"
static const uint32_t SYSTEMBINAPP_PROCESS32[] = {0x21d4a6c3,0x55c830e9,0x2ddba6d6,0x21d22deb,0xdd8b8c0,0x75ca28ff,0x32a7c794,}; // "/system/bin/app_process32"
static const uint32_t SYSTEMBINAPP_PROCESS64[] = {0x21d4a6c3,0x55c830e9,0x2ddba6d6,0x21d22deb,0xdd8b8c0,0x70ca28ff,0x37a7c792,}; // "/system/bin/app_process64"
static const uint32_t SYSTEMBINLINKER[] = {0x21d4a6c3,0x55c830e9,0x2ddba6d6,0x15cc34e6,0x5aa9a1d8,}; // "/system/bin/linker"
static const uint32_t SYSTEMBINLINKER64[] = {0x21d4a6c3,0x55c830e9,0x2ddba6d6,0x15cc34e6,0x6e9fa1d8,0x25fe4282,}; // "/system/bin/linker64"
static const uint32_t SYSTEMBINSH[] = {0x21d4a6c3,0x55c830e9,0x2ddba6d6,0x7ea235f9,}; // "/system/bin/sh"
static const uint32_t SYSTEMBINRUNAS[] = {0x21d4a6c3,0x55c830e9,0x2ddba6d6,0x53cc28f8,0x1ca9bcc2,}; // "/system/bin/run-as"
static const uint32_t SYSTEMBINLOGCAT[] = {0x21d4a6c3,0x55c830e9,0x2ddba6d6,0x1dc532e6,0x52a0a1dc,}; // "/system/bin/logcat"
static const uint32_t INITSVCADBD[] = {0x26c4bb85,0x1ec33bf5,0x2bdaa586,0x78a35ebe,}; // "init.svc.adbd"

#define _S(nom) _decode((sizeof(nom)/4)-1,nom,work)


void *_inotify_thread_handler( void *arg )
//static int _inotify_thread_handler( void *arg )
{
	ALOG("CI:TAG: Inotify thread initializing");
	ASCTI_Item_t item;
	MEMSET(&item, 0, sizeof(item));
	item.test = CTI_TEST_APPLICATIONTAMPERINGDETECTED;
	item.subtest = _SUBTEST_INTERNAL_MONITOR;
	item.data3_type = ASCTI_DT_VRID;

	int nfd = INOTIFY_INIT(); // no EINTR
	if( nfd == -1 ){
		error_report(ERRORBASE+__LINE__,errno,0);
		ALOG("CI:ERR: inotify_init");
		item.data3=ERRORBASE+__LINE__;
		message_add( &item );
		return 0;
	}

	int wd, cnt=0;

	uint32_t work[WORK_MAX];

	if( INOTIFY_ADD_WATCH( nfd, _S(SYSTEMLIBLIBCSO) , IN_DONT_FOLLOW|IN_OPEN|IN_ACCESS ) != -1 ) cnt++;
	if( INOTIFY_ADD_WATCH( nfd, _S(SYSTEMLIB64LIBCSO) , IN_DONT_FOLLOW|IN_OPEN|IN_ACCESS ) != -1 ) cnt++;
	if( INOTIFY_ADD_WATCH( nfd, _S(SYSTEMBINAPP_PROCESS) , IN_DONT_FOLLOW|IN_OPEN|IN_ACCESS ) != -1 ) cnt++;
	if( INOTIFY_ADD_WATCH( nfd, _S(SYSTEMBINAPP_PROCESS32) , IN_DONT_FOLLOW|IN_OPEN|IN_ACCESS ) != -1 ) cnt++;
	if( INOTIFY_ADD_WATCH( nfd, _S(SYSTEMBINAPP_PROCESS64) , IN_DONT_FOLLOW|IN_OPEN|IN_ACCESS ) != -1 ) cnt++;
	if( INOTIFY_ADD_WATCH( nfd, _S(SYSTEMBINLINKER) , IN_DONT_FOLLOW|IN_OPEN|IN_ACCESS ) != -1 ) cnt++;
	if( INOTIFY_ADD_WATCH( nfd, _S(SYSTEMBINLINKER64) , IN_DONT_FOLLOW|IN_OPEN|IN_ACCESS ) != -1 ) cnt++;
	if( INOTIFY_ADD_WATCH( nfd, _S(SYSTEMBINSH) , IN_DONT_FOLLOW|IN_OPEN|IN_ACCESS ) != -1 ) cnt++;
	if( INOTIFY_ADD_WATCH( nfd, _S(SYSTEMBINRUNAS) , IN_DONT_FOLLOW|IN_OPEN|IN_ACCESS ) != -1 ) cnt++;
	if( INOTIFY_ADD_WATCH( nfd, _S(SYSTEMBINLOGCAT) , IN_DONT_FOLLOW|IN_OPEN|IN_ACCESS ) != -1 ) cnt++;

	if( INOTIFY_ADD_WATCH( nfd, _PLATFORM_CONFIG.apk, IN_DONT_FOLLOW|IN_OPEN ) == -1 ){
		error_report(ERRORBASE+__LINE__,errno,0);
		ALOG("CI:ERR: inotify add apk");
		item.data3=ERRORBASE+__LINE__;
		message_add( &item );
		return 0;
	}

	if( cnt == 0 ){
		ALOG("CI:ERR: unable to add any inotify watchers");
		error_report(ERRORBASE+__LINE__,0,0);
		item.data3=ERRORBASE+__LINE__;
		message_add( &item );
		return 0;
	}

#define MAX_PFDS 9
	struct pollfd pfds[MAX_PFDS];
	pfds[0].fd = nfd;
	pfds[0].events = POLL_IN;
	int pfd_i = 1;

	// Our strategy: Zygote creates sockets to connect out to adb for incoming debugger & DDMS
	// connections.  It's hard to recover the exact fd, so instead we take a different
	// approach: just loop through the first 64 file descriptors and take anythign that's
	// a socket into our poll().  On average, there's about 3 to be found.  One of those
	// may be the adbd debugger socket; another is typically the window/surface flinger/input
	// connection, which is quasi nice because as the application is actively used, it
	// will wake us up ... effectively putting us into the lifecycle
	int fd = 0;
	struct stat stt;
	while( fd < 64 ){
		int r = FSTAT(fd, &stt);
		if( r == 0 && (stt.st_mode & S_IFMT) == S_IFSOCK ){
			// it's a socket
			ALOG("CI:TAG: INOTIFY adding socket at fd %d", fd);
			pfds[pfd_i].fd = fd;
			pfds[pfd_i].events = POLL_IN;
			pfd_i++;
			if( pfd_i >= MAX_PFDS ) break;
		}
		fd++;
	}

	// BUG IN OUR STRATEGY: we could poll onto a socket that is pretty chatty, that is unrelated
	// to JDWP.  We see this in Unity.  So what we do is track how frequently a particular FD
	// triggers, and if it exceeds a threshold in a certain time span, we permanently squelch it.
	uint32_t pfds_counts[MAX_PFDS];
	MEMSET( pfds_counts, 0, sizeof(pfds_counts) );


	// SPECIAL: for certain platforms, we have to fall back to Java-based Debug.isDebuggerPresent()
	// calls.  observations_debugger() will internally attach a thread to the JVM as needed, but
	// we run in an infinite loop, and want to avoid having observations_debugger() internally
	// attach and detach to the JVM every call.  So we are going to optimize things by adding
	// this thread to the JVM permanently, if needed, to avoid that thrash.
	if( _PLATFORM_CONFIG.jc_vmd != NULL && _PLATFORM_CONFIG.jm_idc != NULL ){
		JNIEnv *env = NULL;
		int r = (*_PLATFORM_CONFIG.vm)->GetEnv(_PLATFORM_CONFIG.vm, (void**)&env, JNI_VERSION_1_6);
		if( r == JNI_EDETACHED ){
			if( (*_PLATFORM_CONFIG.vm)->AttachCurrentThread(_PLATFORM_CONFIG.vm, &env, NULL) != 0){
				ALOG("CI:ERR: Unable to pre-attach watcher thread");
				error_report(ERRORBASE+__LINE__,0,0);
			}
		}
		else if( r != JNI_OK ){
			ALOG("CI:ERR: watcher thread vm pre-attachment");
			error_report(ERRORBASE+__LINE__,0,0);
			// NOTE: fall through; not ideal, but debugger will attach/unattach as needed internally
		}
	}


	struct timespec ts_now;
	time_t tv_expire;
	int tres = clock_gettime( CLOCK_REALTIME, &ts_now );
	if( tres == -1 ){
		error_report(ERRORBASE+__LINE__,errno,0);
		ALOG("CI:ERR: clock_gettime");
		item.data3=ERRORBASE+__LINE__;
		message_add( &item );
		return 0;
	}
	tv_expire = ts_now.tv_sec;
	time_t cache_expire = ts_now.tv_sec + INOTIFY_CACHE_CLEAR;

	int skips = 0;
	cnt = 0;

	ALOG("CI:TAG: Inotify entering monitoring loop");
	uint8_t buf[256];
	ASSERT( PROP_VALUE_MAX <= sizeof(buf) );
	int timeout = INOTIFY_MERGE_SECONDS_CONFIRMED * 1000;
	uint32_t _dtrack = 0;
	uint32_t _ctr = 0;

	while(1){
		// Wait for data to be ready
		ssize_t res = (ssize_t)POLL(pfds, pfd_i, timeout);
		if( res == -1 ) continue;

		// NOTE: res == 0 upon timeout
		if( res > 0 && (pfds[0].revents & POLLIN) ){ 
			// Read out the actual inotify data
			res = READ( nfd, buf, sizeof(buf) );
			if( res == -1 ) continue;
		}

		int fd_activity = 0;
		if( res > 0 && pfd_i > 1 ){
			int i;
			for( i=1; i<pfd_i; i++){
				if( pfds[i].revents & (POLLHUP|POLLERR|POLLNVAL) ){
					ALOG("CI:TAG: INOTIFY fd %d done", pfds[i].fd);
					pfds[i].fd = -1;
					pfds[i].events = 0;
				}
				else if( pfds[i].revents & POLLIN ){ 
					fd_activity++;
					pfds_counts[i]++;
					if( pfds_counts[i] > INOTIFY_FD_SQUELCH ){
						// Too many triggers within our reset window, this socket is too chatty to be JDWP
						ALOG("CI:TAG: INOTIFY fd %d getting squelched", pfds[i].fd);
						pfds[i].fd = -1;
						pfds[i].events = 0;
					}
				}
			}
		}

		// We actually don't care what events we got, we just re-run our checks

		// Check how recently we ran
		tres = clock_gettime( CLOCK_REALTIME, &ts_now );
		if( tres == -1 ){
			error_report(ERRORBASE+__LINE__,errno,0);
			ALOG("CI:ERR: INOTIFY GETTIME ERR");
			item.data3=ERRORBASE+__LINE__;
			message_add( &item );
			return 0;
		}

		// Only run periodically; NOTE: while will will "skip" this invoke
		// because it's too recent, what we don't want to do is enter in
		// a blocking loop for a long time and not react to something we
		// should be checking.  So what we really wind up doing is "delaying"
		// anything that is skipped to the next invocation boundary, to
		// ensure we run again to re-check whatever caused this.
		if( ts_now.tv_sec < tv_expire ) { 
			skips++;
			timeout = ((tv_expire - ts_now.tv_sec) * 1000) + 10;
			// To prevent tight spins on the fd inotifies, we are going to
			// microsleep here to aggregate
			usleep(200);
			continue; 
		}

		// Check if we should clear our cache
		if( ts_now.tv_sec >= cache_expire ){
			ALOG("CI:TAG: INOTIFY expiring d_cache & resetting counts");
			cache_expire = ts_now.tv_sec + INOTIFY_CACHE_CLEAR;
			_CONFIG.track_debug = 0;
			_dtrack = 0;

			// We also reset our pfds_counts
			MEMSET( pfds_counts, 0, sizeof(pfds_counts) );
		}
		
		ALOG("CI:TAG: INOTIFY checking; skips=%d fd_activity=%d", skips, fd_activity);
		skips=0;

		// Get our delay scheduling
		uint32_t level = 2;
		if( guarded_uint32_get(GUARDED_SLOT_MONLEVEL, &level) > 0 ){
			ALOG("CI:WARN: guarded monlevel get integrity issue");
			// NOTE: guarded_uint32_get reports integrity internally
		}

		if( level == 1 ){
			timeout = INOTIFY_MERGE_SECONDS_ELEVATED * 1000;
			tv_expire = ts_now.tv_sec + INOTIFY_MERGE_SECONDS_ELEVATED;
		}
		else if( level == 0 ){
			timeout = INOTIFY_MERGE_SECONDS_NORMAL * 1000;
			tv_expire = ts_now.tv_sec + INOTIFY_MERGE_SECONDS_NORMAL;
		}
		else {
			timeout = INOTIFY_MERGE_SECONDS_CONFIRMED * 1000;
			tv_expire = ts_now.tv_sec + INOTIFY_MERGE_SECONDS_CONFIRMED;
		}

		// Run debugger observations
		observations_debugger(1, &_dtrack);

		// Run hook observations
		_ctr++;
		int force = level;
		if( (_ctr & RECHECK_INTERVAL) == 0 ) force = 1;
		observations_hooks(force);

		// check for ADBD being turned on
		if( _PLATFORM_CONFIG.adbd == 0 ){
                	int r = property_get(_S(INITSVCADBD), (char*)buf);
                	if( r > 0 && buf[0] == 'r' ){
				ALOG("CI:TAG: INOTIFY detected adb enabled");
                        	// ADBd is running
				ASCTI_Item_t item;
				MEMSET(&item, 0, sizeof(item));
				item.test = CTI_TEST_ADBDRUNNING;
                        	message_add( &item );
                        	_PLATFORM_CONFIG.adbd = 1;
                	}
		}

#if 0
// TODO FIXME: this is causing massive dupes

		// We check libs every 4th invoke
		cnt++;
		if( cnt >= 3 ) {
			observations_libs();
			cnt = 0;
		}
#endif


		// BUGFIX: we can trigger off the JDWP socket pretty fast, and we actually
		// finish our check before the debugger is officially attached.  So, we
		// are going to microsleep and try again.
		if( fd_activity > 0 ){
			usleep(600); 
			observations_debugger(1, &_CONFIG.track_debug);

			tv_expire = ts_now.tv_sec + 1;
			timeout = 500;
		}

		ALOG("CI:TAG: watcher pass done");
	}
}

int watchers_init()
{
        int found = 0, record;
        CHECK_HOOK(pthread_attr_setdetachstate, found, record);
        CHECK_HOOK(pthread_create, found, record);
        CHECK_HOOK(_inotify_thread_handler, found, record);
        REPORT_HOOKING(found, record);

	if( _CONFIG.flag_disable_background_monitor == 0 ){
        	pthread_attr_t attr;
        	if( pthread_attr_init( &attr ) != 0 ){ ALOG("CI:ERR: Failed to attr_init"); return -1; }
        	if( pthread_attr_setdetachstate( &attr, PTHREAD_CREATE_DETACHED ) != 0 ){
                	ALOG("CI:ERR: Failed to set detached");
                	error_report(ERRORBASE+__LINE__,0,0); 
			// This isn't fatal, keep going
		}

		// Create the inotify thread
		pthread_t inotify_thread;
        	if( pthread_create( &inotify_thread, &attr,
               		_inotify_thread_handler, NULL ) != 0 ){
                	ALOG("CI:ERR: Failed to create notify thread");
                	return error_report(ERRORBASE+__LINE__,0,-1); 
		}

	} else {
		ALOG("CI:TAG: Background monitor disabled by config");
		// Send an app-only indicator that no background monitoring is happening,
		// which may or may not be what they want.
		ASCTI_Item_t item;
		MEMSET(&item, 0, sizeof(item));
		item.test = CTI_TEST_BACKGROUNDMONITORINGDISABLED;
		//item.flag_no_send = 1;
		message_add( &item );
	}

	return 0;
}

#endif // GAMEPROTECTLITE
