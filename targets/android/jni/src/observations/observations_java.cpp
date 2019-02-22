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
#include <assert.h>

#include "as_ma_private.h"
#include "observations/observations.h"
#include "as_cti.h"
#include "ascti_tests.h"

#define ERRORBASE 	19000
#define PKG_SIZE	512
#define SIG_SIZE	4096

////////////////////////////////////////////////////////////////////////////

#define WORK_MAX 11

static const uint32_t ANDROIDCONTENTPMPACKAGEMANAGER[] = {0x20c9bb8d,0x54dc21bc,0x77cfb182,0xbc224bb,0x1488ae90,0x3e822eab,0x18a2a495,0x3eac2ea3,0x41f9f986,}; // "android/content/pm/PackageManager"
static const uint32_t GETINSTALLEDPACKAGES[] = {0x1bd9b08b,0x21dc30bb,0x12c4a38a,0x2ade3986,0x16deb9bc,0x5dbf5ae6,}; // "getInstalledPackages"
static const uint32_t ILJAVAUTILLIST[] = {0x1e849cc4,0x24830ef0,0x1a8a8482,0x20bf50b2,0x6fe1c39a,}; // "(I)Ljava/util/List;"
static const uint32_t JAVAUTILLIST[] = {0x33dbb486,0x1de32f7,0x3fefe2c6,0x6c966de9,}; // "java/util/List"
static const uint32_t SIZE[] = {0x37d7bc9f,0x6ca64fc1,}; // "size"
static const uint32_t I[] = {0x52e4fcc4,}; // "()I"
static const uint32_t GET[] = {0x52d9b08b,}; // "get"
static const uint32_t ILJAVALANGOBJECT[] = {0x1e849cc4,0x24830ef0,0x1d9f9d82,0x2ca949b9,0x17afcb88,0x5cce28e9,}; // "(I)Ljava/lang/Object;"
static const uint32_t ANDROIDCONTENTPMPACKAGEINFO[] = {0x20c9bb8d,0x54dc21bc,0x77cfb182,0xbc224bb,0x1488ae90,0x3e822eab,0x17a6a495,0x54cf20ab,}; // "android/content/pm/PackageInfo"
static const uint32_t PACKAGENAME[] = {0x39ceb49c,0x2cda20a3,0x7bc2b29f,}; // "packageName"
static const uint32_t LJAVALANGSTRING[] = {0x24ccbfa0,0x1ed1639f,0x1a83fbac,0x27937284,0x68f6aeb8,}; // "Ljava/lang/String;"
static const uint32_t SIGNATURES[] = {0x3ccabc9f,0x15ce3ba0,0x42b3b798,}; // "signatures"
static const uint32_t LANDROIDCONTENTPMSIGNATURE[] = {0x3ccc99b7,0xed2188d,0x36ccc8b4,0xbd04786,0x29c58fa9,0x5cd3fdc,0x37d4b1eb,0x74863fc1,}; // "[Landroid/content/pm/Signature;"
static const uint32_t VERSIONCODE[] = {0x21dfb09a,0x39c02cad,0x6ed8b79f,}; // "versionCode"
static const uint32_t ANDROIDCONTENTPMSIGNATURE[] = {0x20c9bb8d,0x54dc21bc,0x77cfb182,0xbc224bb,0x1788ae90,0x3d872aa3,0x1f98b08e,0x5cf15bd6,}; // "android/content/pm/Signature"
static const uint32_t TOBYTEARRAY[] = {0x2befba98,0x2df2cb2,0x55dbb29d,}; // "toByteArray"
static const uint32_t B[] = {0x10f6fcc4,0x4b870f9a,}; // "()[B"
static const uint32_t GETINSTALLERPACKAGENAME[] = {0x1bd9b08b,0x21dc30bb,0x4c4a38a,0x3cde3986,0x3ddeb9bc,0x76da3787,}; // "getInstallerPackageName"
static const uint32_t LJAVALANGSTRINGLJAVALANGSTRING[] = {0x33c799c4,0x4990bec,0x7c839ad0,0x468815df,0x20d695ea,0x1dd61cfc,0x3bd7dcc4,0x2b9150f2,0x3aadf5d1,0x41fc1de0,}; // "(Ljava/lang/String;)Ljava/lang/String;"

static const uint32_t LANDROIDCONTENTPMAPPLICATIONINFO[] = {0x36c3b4a0,0x9db288c,0x30c9b4fe,0x17de2ad6,0x77d6bda2,0x50c72eb9,0x63cba289,0x69cc26b8,0x2df69781,0x56a744d7,}; // "Landroid/content/pm/ApplicationInfo;"
static const uint32_t APPLICATIONINFO[] = {0x3edda58d,0x11cd35ba,0xfdea58e,0x5cc838bc,}; // "applicationInfo"
static const uint32_t ANDROIDCONTENTPMAPPLICATIONINFO[] = {0x20c9bb8d,0x54dc21bc,0x77cfb182,0xbc224bb,0x588ae90,0x27853dba,0x99cb380,0x24bc36b7,0x5be98e86,}; // "android/content/pm/ApplicationInfo"
static const uint32_t FLAGS[] = {0x35ccb98a,0x6ebd4aa7,}; // "flags"




#define _S1(nom) _decode((sizeof(nom)/4)-1,nom,work1)
#define _S2(nom) _decode((sizeof(nom)/4)-1,nom,work2)

#ifndef STR_DECODE
#define STR_DECODE
#define _STR_START      0x52add5ec
#endif


////////////////////////////////////////////////////////////////////////////
//
// helper functions
//

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
		ALOG("CI:ERR OBJ %d", n);
		return error_report(ERRORBASE+__LINE__,n,-1);
	}
	return 0;
}

#define JERET(var, n) if(_jerr(env,(void*)var,n)!=0) return;


__attribute__((always_inline))
static inline void java_pkgs(JNIEnv *env)
{
	ASSERT(_PLATFORM_CONFIG.o_pm);
	ALOG("CI:TAG: ENTER java_pkgs");

	uint32_t work1[WORK_MAX], work2[WORK_MAX]; // for obfuscated strings

	// Get packagemanager class and methods
	jclass c_pm = env->FindClass(_S1(ANDROIDCONTENTPMPACKAGEMANAGER));
	JERET( c_pm, 1 );
	jmethodID m_pm_gip = env->GetMethodID( c_pm, _S1(GETINSTALLEDPACKAGES), _S2(ILJAVAUTILLIST) );
	JERET( m_pm_gip, 2 );
	jmethodID m_pm_gipn = env->GetMethodID( c_pm, _S1(GETINSTALLERPACKAGENAME), _S2(LJAVALANGSTRINGLJAVALANGSTRING));
	env->DeleteLocalRef(c_pm);

	// Get List class and methods
	jclass c_list = env->FindClass(_S1(JAVAUTILLIST));
	JERET( c_list, 3 );
	jmethodID m_list_size = env->GetMethodID( c_list, _S1(SIZE), _S2(I) );
	JERET( m_list_size, 4 );
	jmethodID m_list_get = env->GetMethodID( c_list, _S1(GET), _S2(ILJAVALANGOBJECT) );
	JERET( m_list_get, 5 );
	env->DeleteLocalRef(c_list);

	// Look up PackageInfo class and fields
	jclass c_pkgi = env->FindClass(_S1(ANDROIDCONTENTPMPACKAGEINFO));
	JERET( c_pkgi, 7 );
	// fields: packageName, signatures, versionCode
	jfieldID f_pkgnom = env->GetFieldID( c_pkgi, _S1(PACKAGENAME), _S2(LJAVALANGSTRING));
	JERET( f_pkgnom, 10 );
	jfieldID f_sigs = env->GetFieldID( c_pkgi, _S1(SIGNATURES), _S2(LANDROIDCONTENTPMSIGNATURE));
	JERET( f_sigs, 11 );
	jfieldID f_vc = env->GetFieldID( c_pkgi, _S1(VERSIONCODE), "I");
	JERET( f_vc, 12 );
	jfieldID f_app = env->GetFieldID( c_pkgi, _S1(APPLICATIONINFO), _S2(LANDROIDCONTENTPMAPPLICATIONINFO) );
	JERET( f_app, 13 );
	env->DeleteLocalRef(c_pkgi);

	// Look up ApplicationInfo class and flags field
	jclass c_appinfo = env->FindClass( _S1(ANDROIDCONTENTPMAPPLICATIONINFO) );
	JERET( c_appinfo, 15 );
	jfieldID f_flags = env->GetFieldID( c_appinfo, _S1(FLAGS), "I" );
	JERET( f_flags, 16 );
	env->DeleteLocalRef(c_appinfo);

	// Look up Signature class and .toByteArray() method
	jclass c_sig = env->FindClass(_S1(ANDROIDCONTENTPMSIGNATURE));
	JERET( c_sig, 20 );
	jmethodID m_sig_tba = env->GetMethodID( c_sig, _S1(TOBYTEARRAY), _S2(B) );
	JERET( m_sig_tba, 21 );
	env->DeleteLocalRef(c_sig);


	//
	// Call getInstalledPackages(), which returns a list
	//
// http://androidxref.com/6.0.1_r10/xref/frameworks/base/core/java/android/content/pm/PackageManager.java#140
#define GET_SIGNATURES 0x0040
	jobject o_list_pkgs = env->CallObjectMethod( _PLATFORM_CONFIG.o_pm, m_pm_gip, GET_SIGNATURES ); 
	JERET( o_list_pkgs, 25 );

	// Get the list size
	jint count = env->CallIntMethod( o_list_pkgs, m_list_size );
	JERET( o_list_pkgs, 26 );

	// buffer to hold package name we extract
	char pkg[PKG_SIZE]; 
	uint8_t sig[SIG_SIZE];

	//
	// Walk through the returned list of packages
	//

	void *ob_pkg_state = NULL;
	observations_pkgs_start( &ob_pkg_state );

	int i;
	for( i=0; i<count; i++ ){

		jobject o_sig = NULL;
		jobjectArray o_sigs = NULL;
		jstring s_pkgnom = NULL;
		jbyteArray jba_sig1 = NULL;
		int have_sig=0, is_us=0;
		jsize s_pkgnom_sz, sig_sz = 0;
		char *p, *pkg_;
		jint vc = 0;
		jint flags = 0;
		jobject o_appinfo = NULL;

		// Get the next object in the list
		jobject o_pkginfo = env->CallObjectMethod( o_list_pkgs, m_list_get, i );
		if( JERR(o_pkginfo) ) continue;

		// Get the package name
		s_pkgnom = (jstring)env->GetObjectField( o_pkginfo, f_pkgnom );
		if( JERR(s_pkgnom) ) goto cleanup;
		s_pkgnom_sz = env->GetStringUTFLength(s_pkgnom);
		if( s_pkgnom_sz >= (sizeof(pkg)-1) ){
			error_report(ERRORBASE+__LINE__, s_pkgnom_sz, 0);
			goto cleanup;
		}

		// Copy the package name, because we need to lowercase it
#if 1
		MEMSET(pkg, 0, sizeof(pkg));
		pkg_ = (char*)env->GetStringUTFChars( s_pkgnom, NULL );
		if( JERR(pkg_) ) goto cleanup;
		MEMCPY( pkg, pkg_, s_pkgnom_sz );
		env->ReleaseStringUTFChars( s_pkgnom, pkg_ );
#else
		env->GetStringUTFRegion( s_pkgnom, 0, s_pkgnom_sz, pkg );
		pkg[ s_pkgnom_sz ] = 0;
		if( JERR( s_pkgnom ) ) goto cleanup;
#endif

		// Lowercase the package name
		for( p = pkg; *p; ++p ){
			if( *p >='A' && *p <= 'Z' ) *p |= 0x60;
		}
		//ALOG("PKG '%s'", pkg);

		// Get the VC
		vc = env->GetIntField( o_pkginfo, f_vc );
		if( JERR(o_pkginfo) ) goto cleanup;

		// Get the ApplicationInfo & flags
		o_appinfo = env->GetObjectField( o_pkginfo, f_app );
		if( JERR(o_appinfo) ) goto cleanup;
		flags = env->GetIntField( o_appinfo, f_flags );
		if( JERR(o_appinfo) ) goto cleanup;
		env->DeleteLocalRef(o_appinfo);

		// Get the signatures
		o_sigs = (jobjectArray)env->GetObjectField( o_pkginfo, f_sigs );
		if( JERR(o_sigs) || env->GetArrayLength(o_sigs) < 1 ){
			// No sigs or error; run without them
			observations_pkg( vc, ob_pkg_state, pkg, NULL, 0, NULL, 0, flags, &is_us );
			goto cleanup;
		}

		// Get the first signature, which is an object
		o_sig = env->GetObjectArrayElement( o_sigs, 0 );
		if( !JERR(o_sig) ){

			// Call .toByteArray() to convert it to a byte array
			// NOT-MVP-TODO: is it faster to grab the mSignature private byte[] field?
			// It would save an internal alloc & copy.  Field is there on 4.0 - 6.0
			jba_sig1 = (jbyteArray)env->CallObjectMethod( o_sig, m_sig_tba );
			if( !JERR(jba_sig1) ){

				// Extract out the contents of the byte array
				sig_sz = env->GetArrayLength(jba_sig1); // does not throw
				if( sig_sz < sizeof(sig) ){
					env->GetByteArrayRegion(jba_sig1, 0, sig_sz, (jbyte*)sig);
					if( !_exception_check(env) ) have_sig++;
				}
			}
		}

		if( have_sig ){
			observations_pkg( vc, ob_pkg_state, pkg, sig, (uint32_t)sig_sz, NULL, 0, flags, &is_us );
		} else {
			observations_pkg( vc, ob_pkg_state, pkg, NULL, 0, NULL, 0, flags, &is_us );
		}

cleanup:
		// If this is us, look up the installer name
		if( is_us > 0 ){
			ASCTI_Item_t item;
			ctiitem_setup_app( &item );

			jstring s_inst = (jstring)env->CallObjectMethod( _PLATFORM_CONFIG.o_pm, m_pm_gipn, s_pkgnom );
			char * _inst = NULL;
			if( env->ExceptionCheck() ){
				env->ExceptionClear();
				s_inst = NULL;
				// This is more like a SecurityOperationFailure, but the app may be looking for
				// the provision name.  So to ensure it gets something, we are just going to
				// call this provisioning missing.
				item.test = CTI_TEST_PROVISIONINGMISSING;
			} else {
				if( s_inst != NULL ){
					item.test = CTI_TEST_PROVISIONINGPROVIDER;
					_inst = (char*)env->GetStringUTFChars(s_inst, NULL);
					if( _inst != NULL ){
						item.data1 = _inst;
						item.data1_len = STRLEN(_inst);
						item.data1_type = ASCTI_DT_APPLICATION;
					}
				} else {
					item.test = CTI_TEST_PROVISIONINGMISSING;
				}
			}

			message_add( &item );

			if( s_inst != NULL ){
				if( _inst != NULL ) env->ReleaseStringUTFChars(s_inst, _inst);
				env->DeleteLocalRef(s_inst);
			}
		}


		if( s_pkgnom != NULL ) env->DeleteLocalRef(s_pkgnom);
		if( o_sigs != NULL ) env->DeleteLocalRef(o_sigs);
		if( o_sig != NULL ) env->DeleteLocalRef(o_sig);
		if( jba_sig1 != NULL ) env->DeleteLocalRef(jba_sig1);
		env->DeleteLocalRef(o_pkginfo);
	}

	observations_pkgs_finish( ob_pkg_state );

	env->DeleteLocalRef( o_list_pkgs );
	ALOG("CI:TAG: EXIT java_pkgs");
}


extern "C" {

void observations_java()
{
	ASSERT(_PLATFORM_CONFIG.vm);

	// NOTE: when you attach a new thread to the environment, you only get the system classloader.
	// Which means, you can't load app-specific stuff, you don't have access to anything in
	// the app's classes.dex(es).  Everything here uses the cached context object and just
	// Framework classes.

        // We might need to attach an environment
        JNIEnv *env = NULL;
        int do_detach = 0;
        int r = _PLATFORM_CONFIG.vm->GetEnv((void**)&env, JNI_VERSION_1_6);
        if( r == JNI_EDETACHED ){
                if( _PLATFORM_CONFIG.vm->AttachCurrentThread(&env, NULL) != 0){
                        ALOG("CI:ERR: Unable to attach current thread");
                        error_report( ERRORBASE+__LINE__,0,0);
                        return;
                }
                do_detach=1;
        } else if( r != JNI_OK ){
                ALOG("CI:ERR: GetEnv returned error");
                error_report( ERRORBASE+__LINE__,0,0);
                return;
        }

	// Now do java stuff
	java_pkgs( env );

	// Cleanup
	if( do_detach ) _PLATFORM_CONFIG.vm->DetachCurrentThread();
}

} // extern C

