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

#ifndef _OB_EMBPROV_INLINE_C_
#define _OB_EMBPROV_INLINE_C_

#include <errno.h>
#include <sys/types.h>

#include <Security/Security.h>
#include <CoreFoundation/CoreFoundation.h>

#include "as_ma_private.h"
#include "as_cti.h"
#include "ascti_tests.h"

#include "tf_pkcs7.h"
#include "tf_cal.h"

// Cheesy obfuscated string:
#define EMP "emb\ndde\n.mo\nile\nrov\nsio\n"

#define ERRORBASE_OEP 52000

__attribute__((always_inline))
static inline void observations_embedded_provisioning()
{
	char path[ ASMA_PATH_MAX + 24 ];

	ASCTI_Item_t item;

	size_t rplen = STRLEN((const char*)_CONFIG.rpath);
	MEMCPY( path, _CONFIG.rpath, rplen );
	MEMCPY( &path[rplen], EMP, sizeof(EMP) );
	path[rplen + 3] = 'e';
	path[rplen + 7] = 'd';
	path[rplen + 11] = 'b';
	path[rplen + 15] = 'p';
	path[rplen + 19] = 'i';
	path[rplen + 23] = 'n';
	path[rplen + sizeof(EMP)] = 0;
	ALOG("CI:TAG: EMB path=%s", path);

	int ret;
	do {
		ret = OPEN( path, O_RDONLY, 0 );
	} while( ret == -1 && errno == EINTR );
	if( ret == -1 ){
		ALOG("CI:ERR: open embprov");
		ctiitem_setup_app( &item );
		item.test = CTI_TEST_PROVISIONINGMISSING;
		message_add( &item );
		return;
	}

	struct stat stt;
	if( FSTAT(ret, &stt) != 0 ){ // NOTE: no EINTR
		ALOG("CI:ERR: unable to fstat embprov");
		CLOSE(ret);
		error_report( ERRORBASE_OEP+__LINE__, errno, 0);
		ctiitem_setup_app( &item );
		item.test = CTI_TEST_SECURITYOPERATIONFAILED;
		item.data3 = ERRORBASE_OEP+__LINE__;
		item.data3_type = ASCTI_DT_VRID;
		message_add( &item );
		return;
	}

	uint8_t *f = (uint8_t*)MMAP( NULL, stt.st_size, PROT_READ,
		MAP_FILE|MAP_SHARED, ret, 0 );	
	CLOSE(ret);
	if( f == MAP_FAILED ){
		ALOG("CI:ERR: unable to mmap embprov");
		error_report( ERRORBASE_OEP+__LINE__, errno, 0);
		ctiitem_setup_app( &item );
		item.test = CTI_TEST_SECURITYOPERATIONFAILED;
		item.data3 = ERRORBASE_OEP+__LINE__;
		item.data3_type = ASCTI_DT_NUMBER;
		message_add( &item );
		return;
	}

	// Parse the embedded provisioning profile, which is PKC7

#define MAX_SIGNERS 4
	TFS_SignerInfo_t signers[MAX_SIGNERS];
	ret = TFS_PKCS7_Parse( f, stt.st_size, signers, MAX_SIGNERS );
	if( ret == TFS_PKCS7_ERR_MAXSIGNERS ){
		error_report( ERRORBASE_OEP+__LINE__, 0, 0 );
		// Keep going, we have signers
	}
	else if( ret != TFS_PKCS7_ERR_OK ){
		error_report( ERRORBASE_OEP+__LINE__, ret, 0 );
		ctiitem_setup_app( &item );
		item.test = CTI_TEST_PROVISIONINGCORRUPTED;
		message_add( &item );
		goto done;
	}

	// process the signers
	int signer_found = 0;
	uint8_t digest[TCL_SHA256_DIGEST_SIZE];
	uint32_t *u32 = (uint32_t*)digest;

	int i;
	for( i=0; i<MAX_SIGNERS; i++){
		if( signers[i].cert == NULL ) break;
		ALOG("CI:TAG: EMBSIGNER found");

		// If there is more than one signer, then send an alert; we don't
		// expect this to ever happen, and want to know if does
		if( i == 1 ) error_report(ERRORBASE_OEP+__LINE__,0,0);

		TCL_SHA256( signers[i].cert, signers[i].cert_len, digest );

		ctiitem_setup_app( &item );
		item.test = CTI_TEST_PROVISIONINGSIGNER;
		item.data1 = digest;
		item.data1_type = ASCTI_DT_HASHSHA256;
		item.data1_len = sizeof(digest);

		uint8_t subj[512];
		if( TFS_PKCS7_X509_Parse( signers[i].cert, signers[i].cert_len, NULL, 0, (char*)subj, NULL ) == 0 ){
			item.data2 = subj;
			item.data2_len = STRLEN((const char*)subj);
			item.data2_type = ASCTI_DT_X509S;
			ALOG("CI:TAG: EMBSIGNER subject: %s", item.data2);
		}

		// Check against lastdata
		if( i==0 && _CONFIG.laststart.signer2 == (*u32) && _CONFIG.flag_analytics_coalesce > 0 )
		{
			// matches prior
			item.flag_no_send = 1;
		}
		if( i == 0 && _CONFIG.laststart.signer2 != (*u32) ){
			_CONFIG.laststart.signer2 = *u32;
		}

		message_add( &item );
		signer_found++;
	}

	if( signer_found == 0 ){
		error_report( ERRORBASE_OEP+__LINE__, 0, 0 );
		ctiitem_setup_app( &item );
		item.test = CTI_TEST_PROVISIONINGCORRUPTED;
		message_add( &item );
	}

done:	
	MUNMAP( f, stt.st_size );
}

#endif
