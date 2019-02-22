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
#include <pthread.h>

#include "as_ma_private.h"
#include "config.h"
#include "as_cti.h"
#include "ascti_tests.h"
#include "seed.h"

#define WAIT_SECONDS 10
#define ERRORBASE 11000


#ifdef UNITY

// GameProtect/Unity does not support stealth callbacks

void stealth_callbacks(){}
void stealth_callbacks_conclude(){}
void stealth_callbacks_load( JNIEnv *env ){}

# else

__attribute__((always_inline))
inline static void _crash()
{
        uint32_t *ptr = NULL;
        // NULL deref:
        *ptr = 1;

        // Other SIGSEGV
        ptr = (uint32_t*)0xfffffffc;
        *ptr = 2;
}

static void* _crash_handler(void* arg)
{
        _crash();
        return NULL;
}


__attribute__((always_inline))
inline static int _resolve_call( uint8_t *scb, JNIEnv *env, int i )
{
        uint8_t *clazz = scb;
        uint8_t *meth = scb;

	jclass c;
	jmethodID m;

	uint32_t res;

        while( *meth != '|' && *meth != 0 ){ 
		if( (*meth) == '.' ) *meth = '/';
		meth++;
	}
        if( *meth == 0 ){
                goto err;
        }
        *meth = 0;
        meth++;

	ALOG("CI:TAG: SCB Resolving %s/%s", clazz, meth);

	c = env->FindClass((const char*)clazz);
	if( c == NULL || env->ExceptionCheck() == JNI_TRUE ){
		//env->ExceptionDescribe();
		env->ExceptionClear();
		ALOG("CI:ERR: unable to find class '%s'", clazz);
		goto err;
	}
	c = (jclass)env->NewGlobalRef(c);
	if( i == 1 ) _PLATFORM_CONFIG.jc_scb1 = c;
	else _PLATFORM_CONFIG.jc_scb2 = c;

	m = env->GetStaticMethodID( c, (const char*)meth, "(J)J" );
	if( m == NULL || env->ExceptionCheck() == JNI_TRUE ){
		env->ExceptionClear();
		ALOG("CI:ERR: unable to find method '%s'", meth);
		goto err;
	}
	if( i == 1 ) _PLATFORM_CONFIG.jm_scb1 = m;
	else _PLATFORM_CONFIG.jm_scb2 = m;

	ALOG("CI:TAG: SCB resolved %s/%s", clazz, meth);

	return 42;
err:
        ALOG("CI:ERR: ON SCB!");

        ASCTI_Item_t item;
	ctiitem_setup_app( &item );
        item.test = CTI_TEST_STEALTHCALLBACKFAILURE;
        message_add( &item );
        messages_flush(); // this may not finish before we crash...

        if( _CONFIG.flag_scb_failure_crash > 0 ){
                pthread_t crash_thread;
                if( pthread_create( &crash_thread, NULL, _crash_handler, NULL ) != 0 ){
                        // Couldn't spawn crash thread, so crash directly
                        _crash();
                }

                // we are going to wait on the join, which should never happen
                pthread_join( crash_thread, NULL );
                // Shouldn't get here; if we do, just crash directly
                _crash();
        }

        return -1;
}

inline static int _do_call( JNIEnv *env, jclass c, jmethodID m )
{
	ALOG("CI:TAG: Calling scb...");
	uint32_t res = (uint32_t)env->CallStaticLongMethod( c, m, (jlong)(_CONFIG.scb_in ^ SEED_49) );
	if( env->ExceptionCheck() == JNI_TRUE ){
		env->ExceptionClear();
		ALOG("CI:ERR: ex during scb call");
		goto err;
	}
	if( res != (_CONFIG.scb_out ^ SEED_49) ){
		ALOG("CI:ERR: mismatch on expected output");
		goto err;
	}

	return 42;
err:
        ALOG("CI:ERR: ON SCB!");

        ASCTI_Item_t item;
	ctiitem_setup_app( &item );
        item.test = CTI_TEST_STEALTHCALLBACKFAILURE;
        message_add( &item );
        messages_flush(); // this may not finish before we crash...

        if( _CONFIG.flag_scb_failure_crash > 0 ){
                pthread_t crash_thread;
                if( pthread_create( &crash_thread, NULL, _crash_handler, NULL ) != 0 ){
                        // Couldn't spawn crash thread, so crash directly
                        _crash();
                }

                // we are going to wait on the join, which should never happen
                pthread_join( crash_thread, NULL );
                // Shouldn't get here; if we do, just crash directly
                _crash();
        }

        return -1;
}

extern "C" {

void stealth_callbacks_load( JNIEnv *env )
{
	ALOG("CI:TAG: Loading stealth callbacks");

        if( _CONFIG.scb1[0] == 0 ) return;
	_resolve_call( _CONFIG.scb1, env, 1 );
        MEMSET( _CONFIG.scb1, 0, sizeof(_CONFIG.scb1) );

        if( _CONFIG.scb2[0] == 0 ) return;
	_resolve_call( _CONFIG.scb2, env, 2 );
        MEMSET( _CONFIG.scb2, 0, sizeof(_CONFIG.scb2) );
}

static pthread_mutex_t mutex_scb = PTHREAD_MUTEX_INITIALIZER;

void stealth_callbacks_conclude()
{
	// Get the current time, and calculate our maxwait
	struct timespec maxwait;
	int res = clock_gettime( CLOCK_REALTIME, &maxwait );
	if( res == -1 ){
		error_report(ERRORBASE+__LINE__,errno,0);
		ALOG("CI:ERR: scb conclude gettime");
		return;
	}
	maxwait.tv_sec += WAIT_SECONDS;

	do { res = mutex_timedlock( &mutex_scb, &maxwait ); } 
	while( res != 0 && res != ETIMEDOUT );
	if( res == 0 ){
		ALOG("CI:TAG: SCB clean conclude");
		// We got the mutex, so now just unlock it
		do { res = pthread_mutex_unlock( &mutex_scb ); } while(res != 0);
		return;
	}

	if( res == ETIMEDOUT ){
		// Timed out
		ALOG("CI:WARN: SCB conclude timeout");
        	ASCTI_Item_t item;
		ctiitem_setup_app( &item );
        	item.test = CTI_TEST_STEALTHCALLBACKTIMEOUT;
		message_add( &item );
		return;
	}
}

static void* stealth_callbacks_handler( void *arg )
{
        ALOG("CI:TAG: STEALTH CALLBACKS...");

        // We might need to attach an environment
        JNIEnv *env = NULL;
        int do_detach = 0;
        int r = _PLATFORM_CONFIG.vm->GetEnv((void**)&env, JNI_VERSION_1_6);
        if( r == JNI_EDETACHED ){
                if( _PLATFORM_CONFIG.vm->AttachCurrentThread(&env, NULL) != 0){
                        ALOG("CI:ERR: Unable to attach current thread");
                        error_report( ERRORBASE+__LINE__,0,0);
                        return NULL;
                }
                do_detach=1;
        } else if( r != JNI_OK ){
                ALOG("CI:ERR: GetEnv returned error");
                error_report( ERRORBASE+__LINE__,r,0);
                return NULL;
        }


        // Do SCB1
        int ret = _do_call(env, _PLATFORM_CONFIG.jc_scb1, _PLATFORM_CONFIG.jm_scb1);
        if( ret != 42 ){
                // it wasn't successful, and the response should have
                // been handled; we don't need to do scb2 if scb1 failed
		if( do_detach ) _PLATFORM_CONFIG.vm->DetachCurrentThread();
                return NULL;
        }

        // If there is no SCB2, we are done
        if( _PLATFORM_CONFIG.jc_scb2 != NULL ){
        	// Do SCB2
        	ret = _do_call(env, _PLATFORM_CONFIG.jc_scb2, _PLATFORM_CONFIG.jm_scb2);
	}

	do { ret = pthread_mutex_unlock( &mutex_scb ); } while(ret != 0);
	if( do_detach ) _PLATFORM_CONFIG.vm->DetachCurrentThread();

	return NULL;
}

void stealth_callbacks()
{
        // Do we have any callbacks?
        if( _PLATFORM_CONFIG.jc_scb1 == NULL ) return;

	// Get the mutex, which indicates we are going to attempt an scb thread
	int res;
	do { res = pthread_mutex_lock( &mutex_scb ); } while(res != 0);

        // Flush now, if we might crash later
        if( _CONFIG.flag_scb_failure_crash > 0 ) messages_flush();

        pthread_t scb_thread;
        pthread_attr_t attr;

	// Create a detached attr
        if( pthread_attr_init( &attr ) != 0 ){ ALOG("CI:ERR: Failed to attr_init"); goto err; }
        if( pthread_attr_setdetachstate( &attr, PTHREAD_CREATE_DETACHED ) != 0 ){
                ALOG("CI:ERR: Failed to set detached");
                error_report(ERRORBASE+__LINE__,0,0); 
		goto err;
	}

	// Spawn our thread
        if( pthread_create( &scb_thread, &attr, stealth_callbacks_handler, NULL ) != 0 ){
                ALOG("CI:ERR: Failed to create scb thread");
                error_report(ERRORBASE+__LINE__,0,-1); 
		goto err;
	}

	// The mutex is left locked by us; the thread will unlock it when done
	return;

err:
	// error; we have to unlock the mutex because the thread won't
	do { res = pthread_mutex_unlock( &mutex_scb ); } while(res != 0);

}

} // extern C

#endif // UNITY
