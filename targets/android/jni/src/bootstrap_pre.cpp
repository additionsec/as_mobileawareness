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
#include <errno.h>
#include <pthread.h>
#include <dlfcn.h>
#include <stdint.h>

#include <android/asset_manager_jni.h>

#include "as_ma_private.h"
#include "observations/observations.h"
#include "as_cti.h"
#include "ascti_tests.h"

#define ERRORBASE 10000

#include "observations_symbols.inline.cpp"


////////////////////////////////////////////////////////////////////////////
//
// Obufscated strings
//

#define WORK_MAX	20

static const uint32_t COMADDITIONSECURITYMOBILEAWARENESSB[] = {0x7dc0ba8f,0x4fd52db0,0x76c7bb99,0x50dd25b6,0x66ccab9f,0x4fc205ea,0x49ca86da,0x6fd10cf5,0x63f7becc,0x18a62fbe,}; // "com/additionsecurity/MobileAwareness$B"
static const uint32_t DATADIR[] = {0x33d9b488,0x68da2e92,}; // "dataDir"
static const uint32_t IIBBV[] = {0x9e49cc4,0x7bd734d8,0x2caacbd3,}; // "(II[B[B)V"
static const uint32_t ANDROIDAPPACTIVITYTHREAD[] = {0x20c9bb8d,0x54dc21bc,0x2cd1ae80,0x16dc369d,0x20cdb8b0,0xede33be,0x49b3b886,}; // "android/app/ActivityThread"
static const uint32_t CURRENTACTIVITYTHREAD[] = {0x20dfa08f,0x3ada3db4,0x1bceb68a,0x1cce39bf,0x32ceac8c,0x79af4fb2,}; // "currentActivityThread"
static const uint32_t LANDROIDAPPACTIVITYTHREAD[] = {0x33e1fcc4,0x7e26bf4,0x31b0f0c0,0x23e67bec,0x1aeae8d4,0x5f27fe7,0x23fae2d6,0x609332ea,}; // "()Landroid/app/ActivityThread;"
static const uint32_t ANDROIDAPPACTIVITYTHREADAPPBINDDATA[] = {0x20c9bb8d,0x54dc21bc,0x2cd1ae80,0x16dc369d,0x20cdb8b0,0xede33be,0x897b886,0x22bc23ae,0x3cad9097,0x47fc22b5,}; // "android/app/ActivityThread$AppBindData"
static const uint32_t MBOUNDAPPLICATION[] = {0x27c29781,0xcf200b1,0x38e6939c,0x4f61ca1,0x4b93fb94,}; // "mBoundApplication"
static const uint32_t LANDROIDAPPACTIVITYTHREADAPPBINDDATA[] = {0x36c3b4a0,0x9db288c,0x2ed6b6fe,0x9cc0c8d,0x32c09dbf,0xbc92a9c,0x68c0a4a0,0x69d93fb9,0x52e88687,0x12d821b0,0x6585fee5,}; // "Landroid/app/ActivityThread$AppBindData;"
static const uint32_t INSTRUMENTATIONNAME[] = {0x26debb85,0x18c23da9,0x3bdeb69a,0x26c922af,0x69c9a895,}; // "instrumentationName"
static const uint32_t LANDROIDCONTENTCOMPONENTNAME[] = {0x36c3b4a0,0x9db288c,0x30c9b4fe,0x17de2ad6,0x35d48ea2,0x1bdb0288,0x3df899bf,0x7eaa178a,}; // "Landroid/content/ComponentName;"
static const uint32_t DEBUGMODE[] = {0x27cfb088,0x18d10eb1,0x4facf189,}; // "debugMode"
static const uint32_t ANDROIDCONTENTPMAPPLICATIONINFO[] = {0x20c9bb8d,0x54dc21bc,0x77cfb182,0xbc224bb,0x588ae90,0x27853dba,0x99cb380,0x24bc36b7,0x5be98e86,}; // "android/content/pm/ApplicationInfo"
static const uint32_t APPINFO[] = {0x1bdda58d,0x40c330bd,}; // "appInfo"
static const uint32_t LANDROIDCONTENTPMAPPLICATIONINFO[] = {0x36c3b4a0,0x9db288c,0x30c9b4fe,0x17de2ad6,0x77d6bda2,0x50c72eb9,0x63cba289,0x69cc26b8,0x2df69781,0x56a744d7,}; // "Landroid/content/pm/ApplicationInfo;"
static const uint32_t PACKAGENAME[] = {0x39ceb49c,0x2cda20a3,0x7bc2b29f,}; // "packageName"
static const uint32_t LJAVALANGSTRING[] = {0x24ccbfa0,0x1ed1639f,0x1a83fbac,0x27937284,0x68f6aeb8,}; // "Ljava/lang/String;"
static const uint32_t VERSIONCODE[] = {0x21dfb09a,0x39c02cad,0x6ed8b79f,}; // "versionCode"
static const uint32_t FLAGS[] = {0x35ccb98a,0x6ebd4aa7,}; // "flags"
static const uint32_t LJAVALANGOBJECTV[] = {0x38e18ec4,0x4cf10bfb,0x7ce295ca,0x45f921b9,0x31e8a587,0x7a8910f4,}; // "([Ljava/lang/Object;)V"
//static const uint32_t ILJAVALANGSTRINGBV[] = {0x38e19cc4,0x4cf119fb,0x7ce287ca,0x5def2fb9,0x29eda68b,0x34a5078a,0x73c8e8d3,}; // "(ILjava/lang/String;[B)V"
static const uint32_t ILJAVALANGSTRINGBBV[] = {0x38e19cc4,0x4cf119fb,0x7ce287ca,0x5def2fb9,0x29eda68b,0x20d7078a,0x67babefa,}; // "(ILjava/lang/String;[B[B)V"
static const uint32_t V[] = {0x52fbfcc4,}; // "()V"
static const uint32_t JJ[] = {0x18849fc4,0x43f56c9a,}; // "(J)J"

static const uint32_t COMADDITIONSECURITYMOBILEAWARENESSOPERATIONEXCEPTION[] = {0x7dc0ba8f,0x4fd52db0,0x76c7bb99,0x50dd25b6,0x66ccab9f,0x4fc205ea,0x49ca86da,0x6fd10cf5,0x63f7becc,0x7dd622be,0x63ff9c99,0x68e329a2,0x73d68b92,0x18f927a9,}; // "com/additionsecurity/MobileAwareness$OperationException"
static const uint32_t COMADDITIONSECURITYMOBILEAWARENESSLICENSEEXCEPTION[] = {0x7dc0ba8f,0x4fd52db0,0x76c7bb99,0x50dd25b6,0x66ccab9f,0x4fc205ea,0x49ca86da,0x6fd10cf5,0x63f7becc,0x7bcf21be,0x69e1908e,0x7fdb339f,0x7ff780bc,0x14b64380,}; // "com/additionsecurity/MobileAwareness$LicenseException"
static const uint32_t COMADDITIONSECURITYMOBILEAWARENESSSECURITYEXCEPTION[] = {0x7dc0ba8f,0x4fd52db0,0x76c7bb99,0x50dd25b6,0x66ccab9f,0x4fc205ea,0x49ca86da,0x6fd10cf5,0x63f7becc,0x7bc33ebe,0x78f7939e,0x68d60db3,0x6ee7ba85,0x5a617b8,}; // "com/additionsecurity/MobileAwareness$SecurityException"
static const uint32_t GETSYSTEMCONTEXT[] = {0x1d9b08b,0x3fdc30ac,0x6ce8c9c,0x21cf12b4,0x6eaaf5ef,}; // "getSystemContext"
static const uint32_t LANDROIDAPPCONTEXTIMPL[] = {0x33e1fcc4,0x7e26bf4,0x31b0f0c0,0x21e67bec,0xbf7f2d8,0x2ddf65fa,0x6a89e6d3,}; // "()Landroid/app/ContextImpl;"
static const uint32_t ANDROIDCONTENTCONTEXT[] = {0x20c9bb8d,0x54dc21bc,0x77cfb182,0xbc224bb,0x30c9aca3,0x7bdc379c,}; // "android/content/Context"
static const uint32_t GETPACKAGEMANAGER[] = {0x2d9b08b,0x38c320b4,0xef3ba8e,0x38ed20bc,0x7788c795,}; // "getPackageManager"
static const uint32_t LANDROIDCONTENTPMPACKAGEMANAGER[] = {0x33e1fcc4,0x7e26bf4,0x33b0f0c0,0x5bd65f3,0x3af7f6c6,0x10c63af1,0x30cabecb,0x1dc218f6,0x10f2a8c0,0x6ba37bad,}; // "()Landroid/content/pm/PackageManager;"
static const uint32_t SOURCEDIR[] = {0x20d8ba9f,0x12ed2ca2,0x4590d38d,}; // "sourceDir"
static const uint32_t ANDROIDCONTENTPMPACKAGEMANAGER[] = {0x20c9bb8d,0x54dc21bc,0x77cfb182,0xbc224bb,0x1488ae90,0x3e822eab,0x18a2a495,0x3eac2ea3,0x41f9f986,}; // "android/content/pm/PackageManager"
static const uint32_t GETRESOURCESFORAPPLICATION[] = {0xd9b08b,0x2ec730b0,0xadfac9f,0x18d43885,0x3eddafae,0x1cc82d97,0x5ba5aca1,}; // "getResourcesForApplication"
static const uint32_t LANDROIDCONTENTPMAPPLICATIONINFOLANDROIDCONTENTRESRESOURCES[] = {0x3ccc99c4,0xed218fe,0x36ccc8c7,0xbd047f5,0x29c58fda,0x12d42daf,0x34daab9a,0x19dc29b6,0x9ef90a8,0x13f26ac5,0xbddd1fe,0x1bab6ec3,0x119ac7ff,0x8f470c3,0x3d96ccf7,0x2bb074c2,0x47e0a0ff,0x5cd1138a,}; // "(Landroid/content/pm/ApplicationInfo;)Landroid/content/res/Resources;"
static const uint32_t ANDROIDCONTENTRESRESOURCES[] = {0x20c9bb8d,0x54dc21bc,0x77cfb182,0xbc224bb,0x6bd4a692,0x4fc6209a,0x6dc8bdb6,0x2ea1569d,}; // "android/content/res/Resources"
static const uint32_t GETASSETS[] = {0x13d9b08b,0x3ccd30a6,0x6bb0cf88,}; // "getAssets"
static const uint32_t LANDROIDCONTENTRESASSETMANAGER[] = {0x33e1fcc4,0x7e26bf4,0x33b0f0c0,0x5bd65f3,0x38f7f6c6,0x32b966f9,0x1b1fad3,0x23b670c6,0x6791c2f6,0x1cc011a0,}; // "()Landroid/content/res/AssetManager;"
static const uint32_t ISDEBUGGERCONNECTED[] = {0x37e9a685,0xbff20b9,0x33c1ad81,0x3dd38b3,0x4cdcba9c,}; // "isDebuggerConnected"
static const uint32_t DALVIKSYSTEMVMDEBUG[] = {0x24c1b488,0xc9f2cbf,0x3e96a09b,0x20b974aa,0x1abef6b5,0x51df1588,}; // "dalvik/system/VMDebug"

static const uint32_t SYSTEMLIBARMLIBDVMSO[] = {0x21d4a6c3,0x55c830e9,0x2dd7a6d8,0x51c32fe5,0x7ac4a1d2,0x428b2ffe,0x5e6c0c8,}; // "/system/lib/arm/libdvm.so"
static const uint32_t SYSTEMLIBLIBDVMSO[] = {0x21d4a6c3,0x55c830e9,0x2dd7a6d8,0x1acc34e8,0x2687bec5,0x6de65df0,}; // "/system/lib/libdvm.so"
static const uint32_t SYSTEMLIB64LIBARTSO[] = {0x21d4a6c3,0x55c830e9,0x34d7a6d8,0xec272b0,0x35d5f489,0x7edb64fd,}; // "/system/lib64/libart.so"
static const uint32_t SYSTEMLIBLIBARTSO[] = {0x21d4a6c3,0x55c830e9,0x2dd7a6d8,0x1fcc34e8,0x2387a7c1,0x68e644f4,}; // "/system/lib/libart.so"
static const uint32_t _ZN3ART3DBG15GDEBUGGERACTIVEE[] = {0x61e38fb3,0x9e60e8c,0x6ffc9395,0x59c10ffc,0x71c39dc5,0x59e30cfa,0x7bf88ad7,0x389161ca,}; // "_ZN3art3Dbg15gDebuggerActiveE"
static const uint32_t _ZN3ART3DBG16ISDEBUGGERACTIVEEV[] = {0x61e38fb3,0x9e60e8c,0x6ffc9395,0x78f621ff,0x50e6a4c1,0x5af522fc,0x6bf1b9c6,0x28ee17fb,}; // "_ZN3art3Dbg16IsDebuggerActiveEv"
static const uint32_t _Z25DVMDBGISDEBUGGERCONNECTEDV[] = {0x679f8fb3,0x78830a89,0x5cb792b6,0x7aac0cae,0x47ac8c92,0x62a3008b,0x40ba8cb7,0x3d3118b,}; // "_Z25dvmDbgIsDebuggerConnectedv"
static const uint32_t ROBUILDVERSIONSDK[] = {0x3083ba9e,0xf9e20b5,0x2a86a9c6,0x17903be9,0x3391af9c,0x78f04cc6,}; // "ro.build.version.sdk"
static const uint32_t ROPRODUCTCPUABILIST[] = {0x2283ba9e,0xc9626b2,0x38c5ad8c,0xa9223a0,0x2c9bad99,0x67fa3ab0,}; // "ro.product.cpu.abilist"
static const uint32_t ROPRODUCTCPUABI[] = {0x2283ba9e,0xc9626b2,0x38c5ad8c,0xa9223a0,0x45f7ad99,}; // "ro.product.cpu.abi"
static const uint32_t PERSISTSYSDALVIKVMLIB[] = {0x21dfb09c,0x54da30ab,0x2dd4b685,0x8c12cbd,0x318aa08f,0x13876db8,0x54ea8283,}; // "persist.sys.dalvik.vm.lib"
static const uint32_t LIBART[] = {0x33cfbc80,0x68be3bac,}; // "libart"

static const uint32_t FILES[] = {0x3ec4b3c3,0x659a33f8,}; // "/files/"
static const uint32_t FILESAS[] = {0x3ec4b3c3,0x49a33f8,0x53e7e3d6,}; // "/files/as/"

static const uint32_t BUILDCONFIG[] = {0x3bd897c2,0xfea00f0,0x3ffe99c3,0x6c87629f,}; // ".BuildConfig"
static const uint32_t DEBUG[] = {0x7ef90a8,0x5c9e63b1,}; // "DEBUG"

static const uint32_t PROCSELF[] = {0x3ddfa5c3,0x3dd79fe,0x54a0e0cf,}; // "/proc/self"
static const uint32_t STATUS[] = {0x26cca19f,0x7dbd21b4,}; // "status"

#define _STR_START      0x52add5ec
#define _S1(nom) _decode((sizeof(nom)/4)-1,nom,work1)
#define _S2(nom) _decode((sizeof(nom)/4)-1,nom,work2)

#include "seed.h"


////////////////////////////////////////////////////////////////////////////
//
// helper functions
//

static int _resolve_cache_class( JNIEnv *env, const char *cnom, jclass* clazz ){
	jclass cl = env->FindClass(cnom);
	if( cl == NULL ) return -1;
	*clazz = reinterpret_cast<jclass>(env->NewGlobalRef(cl));
	if( *clazz == NULL ) return -1;
	return 0;
}

static int _exception_check(JNIEnv *env){
	if( env->ExceptionCheck() == JNI_TRUE ){
		env->ExceptionClear();
		return 1;
	}
	return 0;
}

#define JERR(var) (_exception_check(env) || (void*)var == NULL )

static int _jerr(JNIEnv *env, void* var, int n)
{
	if( JERR(var) ){
		ALOG("CI:ERR BSP %d", n);
		return error_report(ERRORBASE+__LINE__,n,-1);
	}
	return 0;
}

#define JERET(var, n) if(_jerr(env,(void*)var,n)!=0) return _BOOTSTRAP_SETUP;
#define JERETN1(var, n) if(_jerr(env,(void*)var,n)!=0) return -1;


static int _get_string( JNIEnv *env, char *dst, size_t dst_sz, jstring js )
{
	MEMSET( dst, 0, dst_sz );
	const char *dst_ = env->GetStringUTFChars(js, NULL);
	JERETN1( dst_, __LINE__);
	size_t dsz = STRLEN(dst_);
	if( dsz >= (dst_sz-1) ){ JERETN1(NULL, __LINE__); }
	MEMCPY( dst, dst_, dsz );
	env->ReleaseStringUTFChars(js, dst_);
	return dsz;
}

static jobject _get_field_obj(JNIEnv *env, jclass jc, char const *f, char const *fs, jobject o)
{
	jfieldID j_f = env->GetFieldID(jc, f, fs);
	if(JERR(j_f)) return NULL;
	return env->GetObjectField(o, j_f);
}
static jint _get_field_int(JNIEnv *env, jclass jc, char const *f, jobject o)
{
	jfieldID j_f = env->GetFieldID(jc, f, "I");
	if(JERR(j_f)) return 0;
	return env->GetIntField(o, j_f);
}


extern "C" {

//
// NOTE: config is not const, will be modified/manipulated:
//
int bootstrap_pre( JNIEnv *env, const uint8_t uuid[32], 
	uint8_t *config, uint32_t config_len,
	void(*callback)(int,int,ASCTI_Item_t*) )
{
	uint32_t work1[WORK_MAX], work2[WORK_MAX]; // for obfuscated strings
	uint32_t flags_local = 0;
	int res, r = 0;
	if( uuid == NULL || config == NULL ){ JERET(NULL,__LINE__); }

	// TODO: this should return already init?
	if( _CONFIG.flag_configured ){ JERET(NULL,__LINE__); } 

	ALOG("CI:TAG: Bootstrap Pre Start");

	//
	// Variable decls, front-loaded for switch accomodation
	//
	jobject o_t, o_abd, o_ai;
	jclass c_at, c_abd, c_ai;
	char appnom[sizeof(_CONFIG.pkg)];
	char appver[sizeof(_CONFIG.pkgver)];
	char rpath[ASMA_PATH_MAX];


	// Save a reference to the VM
	if( env->GetJavaVM( &_PLATFORM_CONFIG.vm ) != 0 ) { JERET(NULL,__LINE__); }

	// Control flow flattening
	uint32_t seed = SEED_START;
	while(1){
	  uint32_t s = _SEED_NEXT(seed);
	  switch(s){

	case SEED_1:
	{
		// Get current activity thread object
		c_at = env->FindClass(_S1(ANDROIDAPPACTIVITYTHREAD));
		JERET(c_at, __LINE__);
		jmethodID m_at_ca = env->GetStaticMethodID( c_at, _S1(CURRENTACTIVITYTHREAD), _S2(LANDROIDAPPACTIVITYTHREAD));
		JERET(m_at_ca, __LINE__);
		o_t = env->CallStaticObjectMethod( c_at, m_at_ca );
		JERET(o_t, __LINE__);
	}
	break;

	case SEED_2:
	{
		// Get the system context, to get the package manager object
		jmethodID m_at_sc = env->GetMethodID( c_at, _S1(GETSYSTEMCONTEXT), _S2(LANDROIDAPPCONTEXTIMPL) );
		JERET(m_at_sc, __LINE__);
		jclass c_ctx = env->FindClass(_S1(ANDROIDCONTENTCONTEXT));
		JERET(c_ctx, __LINE__);
		jobject o_ctx = env->CallObjectMethod( o_t, m_at_sc );
		JERET(o_ctx, __LINE__);
		_PLATFORM_CONFIG.o_ctx = env->NewGlobalRef(o_ctx);
		JERET( _PLATFORM_CONFIG.o_ctx, __LINE__);
		jmethodID m_ctx_pm = env->GetMethodID( c_ctx, _S1(GETPACKAGEMANAGER), _S2(LANDROIDCONTENTPMPACKAGEMANAGER) );
		JERET(m_ctx_pm, __LINE__);
		jobject o_pm = env->CallObjectMethod(o_ctx, m_ctx_pm);
		JERET(o_pm, __LINE__);
		_PLATFORM_CONFIG.o_pm = env->NewGlobalRef(o_pm);
		JERET(_PLATFORM_CONFIG.o_pm, __LINE__);

		env->DeleteLocalRef(c_ctx);
		env->DeleteLocalRef(o_ctx);
	}
	break;

	case SEED_3:
	{
		// Get AppBindData class
		c_abd = env->FindClass(_S1(ANDROIDAPPACTIVITYTHREADAPPBINDDATA));
		JERET(c_abd, __LINE__);
	}
	break;

	case SEED_4:
	{
		// Get bound abd object
		o_abd = _get_field_obj(env, c_at, _S1(MBOUNDAPPLICATION), _S2(LANDROIDAPPACTIVITYTHREADAPPBINDDATA), o_t);
		JERET(o_abd, __LINE__);
	}
	break;

	case SEED_5:
	{
		// Check if instrumented
		jobject o_i = _get_field_obj(env, c_abd, _S1(INSTRUMENTATIONNAME), _S2(LANDROIDCONTENTCOMPONENTNAME), o_abd); 
		if( o_i != NULL ){ 
			flags_local |= FLAG_INSTRUMENTATION; 
			env->DeleteLocalRef(o_i);
		}
	}
	break;

	case SEED_6:
	{
		// Check if in debug mode
		jint i_dm = _get_field_int(env, c_abd, _S1(DEBUGMODE), o_abd);
		if( i_dm > 0 ){ flags_local |= FLAG_DEBUGMODE; }
	}
	break;

	case SEED_7:
	{
		// Get the ApplicationInfo object
		c_ai = env->FindClass(_S1(ANDROIDCONTENTPMAPPLICATIONINFO));
		JERET(c_ai, __LINE__);
	}
	break;

	case SEED_8:
	{
		o_ai = _get_field_obj(env, c_abd, _S1(APPINFO), _S2(LANDROIDCONTENTPMAPPLICATIONINFO), o_abd); 
		JERET(o_ai, __LINE__);
	}
	break;

	case SEED_9:
	{
		// Clean up some unused globals
		env->DeleteLocalRef(c_abd);
		env->DeleteLocalRef(o_abd);
	}
	break;

	case SEED_10:
	{
		// Get the package name from the ApplicationInfo object
		jstring o_pkg = (jstring)_get_field_obj(env, c_ai, _S1(PACKAGENAME), _S2(LJAVALANGSTRING), o_ai); 
		JERET(o_pkg, __LINE__);
		int r = _get_string( env, appnom, sizeof(appnom), o_pkg );
		env->DeleteLocalRef( o_pkg );
		if( r == -1 ){ JERET(NULL, __LINE__); }
		ALOG("CI:PKG: %s", appnom);
	}
	break;

	case SEED_11:
	{
		// Get the version code
		// NOTE: recovered at a later time
		appver[0]=0;
	}
	break;

	case SEED_12:
	{
		// Get the flags
		jint i_flags = _get_field_int(env, c_ai, _S1(FLAGS), o_ai);
		// FLAG_DEBUGGABLE = 1<<1
		if( i_flags & (1<<1) ){ flags_local |= FLAG_DEBUGGABLE; }
	}
	break;

	case SEED_13:	
	{
		// ai.sourceDir
		jstring o_sd = (jstring)_get_field_obj(env, c_ai, _S1(SOURCEDIR), _S2(LJAVALANGSTRING), o_ai); 
		JERET(o_sd, __LINE__);
		int r = _get_string( env, _PLATFORM_CONFIG.apk, sizeof(_PLATFORM_CONFIG.apk), o_sd );
		env->DeleteLocalRef( o_sd );
		if( r == -1 ){ JERET(NULL, __LINE__); }
		ALOG("CI:APK: %s", _PLATFORM_CONFIG.apk);
	}
	break;

	case SEED_14:	
	{
		// Get our basepath (ai.dataDir)
		jstring o_dd = (jstring)_get_field_obj(env, c_ai, _S1(DATADIR), _S2(LJAVALANGSTRING), o_ai); 
		JERET(o_dd, __LINE__);
		int r = _get_string( env, rpath, sizeof(rpath) - 10, o_dd );
		env->DeleteLocalRef( o_dd );
		if( r == -1 ){ JERET(NULL, __LINE__); }

		// Quick base create, if it fails, that's OK
		rpath[r] = 0;
		MKDIR(rpath, 0711); // INTENTIONALLY NOT CHECKING ERROR

		// BUGFIX:
		// SITUATION: we are using files/as/, and files/ may not exist.  If we
		// mkdir the whole thing, it will fail due to lack of /files/.  So
		// we are going to mkdir on files/ just in case.  If it fails, then
		// we just keep going and will puke later in bootstrap anyways.
		MEMCPY( &rpath[r], _S1(FILES), 7 );
		MKDIR(rpath, 0711); // INTENTIONALLY NOT CHECKING ERROR
		
		MEMCPY( &rpath[r], _S1(FILESAS), 10 );
		rpath[r+10] = 0;
		ALOG("CI:DATADIR: %s", rpath);
	}
	break;

	case SEED_15:
	{
		// Get a reference to the AssetManager object
		jclass c_pm = env->FindClass(_S1(ANDROIDCONTENTPMPACKAGEMANAGER));
		JERET( c_pm, __LINE__ );
		jmethodID m_grfa = env->GetMethodID(c_pm, _S1(GETRESOURCESFORAPPLICATION), 
			_S2(LANDROIDCONTENTPMAPPLICATIONINFOLANDROIDCONTENTRESRESOURCES));
		JERET( m_grfa, __LINE__ );
		jobject o_res = env->CallObjectMethod(_PLATFORM_CONFIG.o_pm, m_grfa, o_ai);
		JERET( o_res, __LINE__ );
		jclass c_res = env->FindClass(_S1(ANDROIDCONTENTRESRESOURCES));
		JERET( c_res, __LINE__ );
		jmethodID m_ga = env->GetMethodID(c_res, _S1(GETASSETS), _S2(LANDROIDCONTENTRESASSETMANAGER));
		JERET( m_ga, __LINE__ );
		jobject o_am = env->CallObjectMethod(o_res, m_ga);
		JERET( o_am, __LINE__ );

		// TODO: new global ref on this:
		_PLATFORM_CONFIG.am = AAssetManager_fromJava( env, o_am );
		JERET( _PLATFORM_CONFIG.am, __LINE__ );

		env->DeleteLocalRef(c_pm);
		env->DeleteLocalRef(c_res);
		env->DeleteLocalRef(o_res);
		env->DeleteLocalRef(o_am);
	}
	break;

	case SEED_16:
	{
		// Clean up remaining unused globals
		env->DeleteLocalRef(c_ai);
		env->DeleteLocalRef(o_ai);
	}
	break;

	case SEED_17:
	{
		// Open /proc/self/status
		int dfd;
		do { dfd = OPENAT(AT_FDCWD,_S1(PROCSELF),O_RDONLY|O_DIRECTORY,0); }
		while( dfd == -1 && errno == EINTR );
		if( dfd == -1 ){ JERET(NULL,__LINE__); }

		do { _PLATFORM_CONFIG.fd_self_status = OPENAT(dfd, _S1(STATUS), O_RDONLY, 0); }
		while( _PLATFORM_CONFIG.fd_self_status == -1 && errno == EINTR );
		CLOSE(dfd);
		if( _PLATFORM_CONFIG.fd_self_status == -1 ){ JERET(NULL,__LINE__); }
	}
	break;

	case SEED_18:
	{
		// This sequence is a PITA dance that sufficiently covers:
		// - older DVM-based devices ( <= 4.4 )
		// - KitKat (4.4) ART-preview devices
		// - Lollipop (5.0) and beyond, with special accomodation for 6.0 and beyond
		// - ARM emulation (libhoudini) on x86 devices
		// - Crashes on x86 emulator image for API 19 (only)
		// -- BUG: https://code.google.com/p/android/issues/detail?id=61799
		//
		// Note: everything you know about dlopen/dlsym goes out the window when trying to
		// find the recipe that covers the above.  We've seen in testing some ART devices
		// that won't find a dlopen() return, but are happy with RTLD_DEFAULT. Then we've
		// also seen ART devices that are the exact opposite.  That's not including the
		// straight linker bug that causes crash (see bug URL, prior), triggered by dlsym().

		// Get the sdk value property
		char prop_value[PROP_VALUE_MAX];
		int r = property_get(_S1(ROBUILDVERSIONSDK), prop_value);
		if( r == 2 ){
			_PLATFORM_CONFIG.api = 10 * (prop_value[0] - '0');
			_PLATFORM_CONFIG.api += (prop_value[1] - '0');
		} else {
			// Couldn't find a valid sdk version, or it's API < 10
			return error_report(ERRORBASE+__LINE__,r,_BOOTSTRAP_SETUP);
		}
		ALOG("CI:TAG: SDK=%d", _PLATFORM_CONFIG.api);

		// Enforce our minimum SDK level, and a sane upper value
		// NOTE: we don't cap it at actual max API level, because every +3
		// months it risks changing and killing apps in the market.  So
		// we sanity check to something notably higher.
		if( _PLATFORM_CONFIG.api < 14 || _PLATFORM_CONFIG.api > 40 ){ JERET(NULL,__LINE__); }

		// SPECIAL: if we are ARM, we need to see if this is an x86 device
		// emulating ARM.  That affects some of our paths.
#ifdef __arm__
		r = 0;
		if( _PLATFORM_CONFIG.api > 19 )
			r = property_get(_S1(ROPRODUCTCPUABILIST), prop_value);
		if (r == 0) r = property_get(_S1(ROPRODUCTCPUABI), prop_value);
		if( r > 0 && prop_value[0] == 'x' ){
			_PLATFORM_CONFIG.is_x86_emulating_arm = 1;
			ALOG("CI:TAG: This is x86 emulating ARM");
		}
#endif

		// Figure out if it's ART
		int is_art = 0;
		if( _PLATFORM_CONFIG.api > 19 ) is_art++;	// Always ART
		else if( _PLATFORM_CONFIG.api == 19 ){
			// Could be ART developer preview on KitKat
			r = property_get(_S1(PERSISTSYSDALVIKVMLIB), prop_value); 
			if( r >= 9 && MEMCMP(prop_value, _S1(LIBART), 6) == 0 ) is_art++;
		}
		// Otherwise, always DVM

		if( is_art > 0 ){ // Also implies is_n
			// ART based system, go straight to ART -- also have RTLD_NOLOAD benefit
			void *h = (void*)RTLD_DEFAULT;

			// N/7.0 and later doesn't allow dlopen to arbitrary libraries
			if( _PLATFORM_CONFIG.api < 24 ){
#ifdef __LP64__
				h = dlopen(_S1(SYSTEMLIB64LIBARTSO), RTLD_LAZY);
#else
				h = dlopen(_S1(SYSTEMLIBLIBARTSO), RTLD_LAZY);
#endif
			}

			if( h == NULL ) h = (void*)RTLD_DEFAULT;
			_PLATFORM_CONFIG.art_gdebuggeractive = (uint8_t*)dlsym( h, _S1(_ZN3ART3DBG15GDEBUGGERACTIVEE) );
			if( _PLATFORM_CONFIG.art_gdebuggeractive == NULL ){
				_PLATFORM_CONFIG.art_isdebuggeractive = dlsym( h, _S1(_ZN3ART3DBG16ISDEBUGGERACTIVEEV) );
			}
		}
		else {
			// DVM based system
			void *h = dlopen(_S1(SYSTEMLIBLIBDVMSO), RTLD_LAZY);
			if( h == NULL ) h = (void*)RTLD_DEFAULT;
			_PLATFORM_CONFIG.dvm_dbg_isdebuggerconnected = dlsym( h, _S1(_Z25DVMDBGISDEBUGGERCONNECTEDV) );
		}
	}
	
	break;

	case SEED_19:
	{
		// We need to find at least one of them
		if( _PLATFORM_CONFIG.art_gdebuggeractive == NULL && 
			_PLATFORM_CONFIG.art_isdebuggeractive == NULL &&
			_PLATFORM_CONFIG.dvm_dbg_isdebuggerconnected == NULL )
		{ 
#if 0
#ifdef __arm__
			// SPECIAL: for ARM on X86 emulation, we have to use Java call, since native code direct is not available
			if( _PLATFORM_CONFIG.is_x86_emulating_arm > 0 )
			{
				_PLATFORM_CONFIG.jc_vmd = env->FindClass("dalvik/system/VMDebug");
				JERET(_PLATFORM_CONFIG.jc_vmd,__LINE__); 
				_PLATFORM_CONFIG.jc_vmd = (jclass)env->NewGlobalRef(_PLATFORM_CONFIG.jc_vmd);
				JERET(_PLATFORM_CONFIG.jc_vmd,__LINE__); 
				_PLATFORM_CONFIG.jm_idc = env->GetStaticMethodID( _PLATFORM_CONFIG.jc_vmd, "isDebuggerConnected", "()Z" );
				JERET(_PLATFORM_CONFIG.jm_idc,__LINE__);
			} else {
				ALOG("CI:ERR: Couldn't find a debugger symbol");
				JERET(NULL,__LINE__); 
			}
#else
			ALOG("CI:ERR: Couldn't find a debugger symbol");
			JERET(NULL,__LINE__); 
#endif
#endif
			// There are multiple cases (ARM on X86, Android N) where we have to fall back to a Java call
			_PLATFORM_CONFIG.jc_vmd = env->FindClass(_S1(DALVIKSYSTEMVMDEBUG));
			JERET(_PLATFORM_CONFIG.jc_vmd,__LINE__); 
			_PLATFORM_CONFIG.jc_vmd = (jclass)env->NewGlobalRef(_PLATFORM_CONFIG.jc_vmd);
			JERET(_PLATFORM_CONFIG.jc_vmd,__LINE__); 
			_PLATFORM_CONFIG.jm_idc = env->GetStaticMethodID( _PLATFORM_CONFIG.jc_vmd, _S1(ISDEBUGGERCONNECTED), "()Z" );
			JERET(_PLATFORM_CONFIG.jm_idc,__LINE__);
		}

		// Mark the debugger as ready
		_CONFIG.flag_debugger_go = 1;
	}
	break;

	case SEED_20:
	{
		// Init our proxy (class lookups & caching)
		res = proxy_init( env );
		if( res != 0 ){
			ALOG("CI:ERR: Proxy_init returned %d", res);
			JERET(NULL, (res << 16) | __LINE__);
		}
	}
	break;

	case SEED_21:
	{
		// Do our bootstrap
		res = bootstrap_ex( appnom, appver, rpath, rpath, uuid, callback, flags_local, config, config_len );
	}
	break;

	case SEED_22:
	{
		// Resolve our stealth callbacks (cache stuff that is later called within bootstrap)
		// SPECIAL: we must do this now, because this thread has the app's classloader while
		// arbitrarily attached threads only get the system classloader
		stealth_callbacks_load( env );
	}
	break;

	case SEED_23:
	{
	  if( res == _BOOTSTRAP_OK && _CONFIG.pkg[0] != 0 ){
		// See if we can find a BuildConfig and get DEBUG boolean field; we do this here while we have
		// access to the apps main UI thread, classloader, etc.

		// Construct the class name using the pkg name and appending ".BuildConfig"
		char bc[ ASMA_PKG_MAX + 13 ];
		MEMCPY( bc, _CONFIG.pkg, _CONFIG.pkg_sz );
		MEMCPY( &bc[_CONFIG.pkg_sz], _S1(BUILDCONFIG), 12 );
		bc[_CONFIG.pkg_sz + 12] = 0;

		// Convert dots to slashes (required FindClass form)
		int i;
		for( i=0; i<(_CONFIG.pkg_sz+12); i++){ if( bc[i] == '.' ) bc[i] = '/'; }

		env->ExceptionClear();
		jclass clazz_bc = env->FindClass(bc);
		if( !env->ExceptionCheck() && clazz_bc != NULL ){
			// Found the BuildConfig class
			//ALOG("CI:TAG: BC Found '%s'", bc);

			// try to get the field value
			jfieldID f_d = env->GetStaticFieldID(clazz_bc, _S1(DEBUG), "Z");
			if( !env->ExceptionCheck() && f_d != NULL ){
				jboolean b = env->GetStaticBooleanField(clazz_bc, f_d);
				if( b ){
					ALOG("CI:TAG: BC This is a debug build");
					ASCTI_Item_t item;
					ctiitem_setup_app( &item );
					item.test = CTI_TEST_DEBUGBUILD;
					message_add( &item );
				}
			}
		} else {
			ALOG("CI:WARN: BC Unable to find '%s'", bc);
			// This is not considered fatal or alert-worthy; some build systems don't
			// generate a BuildConfig class, so we just act as if it's not there
		}
		env->ExceptionClear();
		if( clazz_bc != NULL ) env->DeleteLocalRef(clazz_bc);
	  }
	}
	break;

	case SEED_24:
	{
#ifdef __arm__
		// Report if we are ARM on x86 (have to do after bootstrap, so messages are online)
		if( _PLATFORM_CONFIG.is_x86_emulating_arm == 1 ){
			ASCTI_Item_t item;
			ctiitem_setup_app( &item );
			item.test = CTI_TEST_ARMONX86;
			message_add( &item );
		}
#endif
	}
	break;

	case SEED_25:
	{
		// We have to do symbol observations here as well, due to the same classloader issue
		if( res == _BOOTSTRAP_OK ){
			observations_symbols(env);
		}
	}
	break;

	case SEED_26:
		ALOG("CI:TAG: bootstrap_pre done res=%d", res);
		return res;

	default:
		ALOG("CI:ERR: left switch cases");
		return _BOOTSTRAP_INTEGRITY;

	  } // switch
	} // while
}

} // extern C

