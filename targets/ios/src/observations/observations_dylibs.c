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

#include <sys/types.h>
#include <sys/sysctl.h>
#include <unistd.h>
#include <sys/utsname.h>
#include <sys/syscall.h>
#include <arpa/inet.h>	// For ntohl

#include <dlfcn.h>
#include <mach-o/dyld.h>
#include <mach-o/fat.h>
#include <mach-o/dyld_images.h>
#include <Security/Security.h>
#include <CoreFoundation/CoreFoundation.h>

#include <mach/mach.h>
#include <mach/vm_region.h>

#include "as_ma_private.h"
#include "ascti_tests.h"
#include "as_defs_flags.h"

#include "tf_pkcs7.h"
#include "tf_cal.h"

#include "observations/checkhook.h"

#define ERRORBASE	51000

#include "observations_item_common.inline.c"
#include "observations_debugger.inline.c"
#include "observations_hooks.inline.c"

#define WORK_MAX_D	2
static const uint32_t PREFIXD[] = {0x1e991ad,0x5a9821b6,}; // "ADDSEC"
#define _SD(nom) _decode((sizeof(nom)/4)-1,nom,work)

static inline void _lc_code_sig( uint8_t *lc_code_signature, uint32_t lc_code_signature_len );

__attribute__((always_inline))
static inline int _load_cs_from_executable(const char *fname, const struct mach_header *mh, uint32_t cs_off, uint32_t cs_len)
{
	ALOG("CI:TAG: SIG LOAD off=%x len=%x", cs_off, cs_len);

	int ret = OPEN( fname, O_RDONLY, 0 );
	if( ret == -1 ){
		ALOG("CI:ERR: unable to open exe file");
		return 1;
	}

	struct stat stt;
	if( FSTAT( ret, &stt ) != 0 ){ // NOTE: no EINTR
		ALOG("CI:ERR: unable to fstat exe file");
		CLOSE(ret);
		return 2;
	}

        uint8_t *f = (uint8_t*)MMAP( NULL, stt.st_size, PROT_READ, MAP_FILE|MAP_SHARED, ret, 0 );
        CLOSE(ret);
        if( f == MAP_FAILED ){
                ALOG("CI:ERR: unable to mmap exe file");
		return 4;
        }


	// While it's mapped, let's hash the whole file as a measurement
      	uint8_t digest[TCL_SHA256_DIGEST_SIZE];
	uint32_t *u32 = (uint32_t*)digest;
	TCL_SHA256( f, stt.st_size, digest );

	ASCTI_Item_t item;
	MEMSET(&item, 0, sizeof(item));
	item.test = CTI_TEST_APPLICATIONMEASUREMENT;
	item.subtest = _SUBTEST_APPMEASURE_FILE;
	item.data1 = digest;
	item.data1_type = ASCTI_DT_HASHSHA256;
	item.data1_len = TCL_SHA256_DIGEST_SIZE;
	item.data2 = (void*)fname;
	item.data2_type = ASCTI_DT_FILE;
	item.data2_len = STRLEN(fname);

	if( _CONFIG.laststart.measure1 == *u32 && _CONFIG.flag_analytics_coalesce > 0 ){
		item.flag_no_send = 1;
	} else {
		_CONFIG.laststart.measure1 = *u32;
	}
	message_add( &item );

	ret = 99;

	struct fat_header fat;
	MEMCPY( &fat, f, sizeof(struct fat_header) );
	int swapped = 0;
	if( fat.magic == FAT_CIGAM ){
		swapped++;
		fat.nfat_arch = ntohl(fat.nfat_arch);
		fat.magic = ntohl(fat.magic);
	}

	uint8_t *cs_start = NULL;

	if( fat.magic == FAT_MAGIC ){
		// Fat, find the right slice
		// Modeled after Apple codesign.c
		uint32_t slices = fat.nfat_arch;

		// Sanity check our slice count
		if( slices > 16 ){ ret = 98; goto done; }

		struct fat_arch *arch_p = (struct fat_arch*)(f + sizeof(struct fat_header));
		struct fat_arch arch;

		int i;
		for(i=0; i<slices; i++){
			MEMCPY( &arch, arch_p, sizeof(struct fat_arch) );
			if( swapped ){
				arch.cputype = ntohl(arch.cputype);
				arch.cpusubtype = ntohl(arch.cpusubtype);
				arch.offset = ntohl(arch.offset);
			}
			if( arch.cputype != mh->cputype || arch.cpusubtype != mh->cpusubtype ){
				//ALOG("FAT: non-matching arch %d/%d", arch.cputype, arch.cpusubtype);
				arch_p += 1;
				continue;
			}

			// Sanity check the offset; NOTE: this isn't perfect, it's meant
			// more for quick corruption catching.
			if( arch.offset >= stt.st_size ){ ret = 97; goto done; }

			// matches cpu types; now check for MH header
			struct mach_header *fmh = (struct mach_header*)(f + arch.offset);
			if( fmh->magic != MH_MAGIC && fmh->magic != MH_MAGIC_64 ){
				ALOG("CI:ERR: FAT: didn't point to MH");
				arch_p += 1;
				continue;
			}

// TODO sanity check the cs_off/cs_len w/ file size
		
			// We found a matching header; go for it	
			ALOG("CI:TAG: FAT: slice[%d] matches runtime mh", i);		
			cs_start = f + arch.offset + cs_off;
			goto check;
		}

		// none of the slices matched
		goto done; // leaves ret=99

	} else {
		// Non-fat, confirm mh & continue
		struct mach_header *fmh = (struct mach_header*)f;
		if( fmh->cputype != mh->cputype || fmh->cpusubtype != mh->cpusubtype ){
			ALOG("CI:ERR: Didn't match cpu types");
			ret = 5; 
			goto done;
		}

		// Looks good, now parse
		cs_start = f + cs_off;
		// fall thru
	}

check:
	if( (size_t)(cs_start - f) > stt.st_size ){ ret = 96; goto done; }
	if( cs_start == NULL ){ ret = 95; goto done; }

	// This will report signers, or report errors; either way, the job of this function
	// is a success
	_lc_code_sig( cs_start, cs_len );
	ret = 0;

done:
	MUNMAP(f, stt.st_size);
	return ret;
}


// based on https://github.com/ddeville/ImageLogger/blob/master/Shared/LLImageLogger.m

__attribute__((always_inline))
static inline uint32_t _image_header_size(const struct mach_header *mh)
{
	bool is_header_64_bit = (mh->magic == MH_MAGIC_64 || mh->magic == MH_CIGAM_64);
	return (is_header_64_bit ? sizeof(struct mach_header_64) : sizeof(struct mach_header));
}

#define CACHE_SIZE 32
static uint64_t        _cache[CACHE_SIZE] = {0};
static uint8_t         _cache_index = 0;

static void _image_callback( const struct mach_header *mh, intptr_t slide )
{
	int found = 0, record;
	CHECK_HOOK(dladdr, found, record);
	REPORT_HOOKING(found, record);

	uint32_t work[WORK_MAX_D];
	_SD(PREFIXD);

	Dl_info image_info;
	if( dladdr(mh, &image_info) == 0 || image_info.dli_fname == NULL || image_info.dli_fname[0] == 0){
		ALOG("CI:WARN: dladdr failed on mach %p", mh);
		error_report( ERRORBASE+__LINE__, 0, 0 );
		return;
	}

	const char *image_name = image_info.dli_fname;
	size_t image_name_sz = STRLEN(image_name);
	const intptr_t image_base_address = (intptr_t)image_info.dli_fbase;
	//ALOG("CI:TAG: Dylib=%s", image_name);

#if 1
	// Special interruption: do a debugger & hooks check if we are post-completion
	//
	if( _CONFIG.flag_startup_completed > 0 ){
		observations_debugger(0, &_CONFIG.track_debug);
		observations_hooks(0, 0);
	}
#endif

	//
	// Field data collection, if warranted
	//
	if( _CONFIG.flag_fdc > 0 ){
		// Hash the image name for lookup
		uint8_t hash[TCL_MD5_DIGEST_SIZE];
		TCL_MD5_2( (uint8_t*)work, 6, (uint8_t*)image_info.dli_fname,
			(uint32_t)STRLEN(image_info.dli_fname), hash );

		//
		// Check if we know about this dylib/framework	
		//
		uint32_t flags2=0;
		uint16_t id2=0;
		int res = TFDefs_Hash_Lookup( &_CONFIG.defs_as, ASDEFS_SECTION_APPROVEDDYLIBS, (uint8_t*)hash, &flags2, &id2 );
		if( res != TFDEFS_FOUND ){
       		         	ASCTI_Item_t item;
				MEMSET( &item, 0, sizeof(item) );
				item.test = CTI_TEST_FDC;
       	         		item.subtest = FDC_LIBRARY;
       	         		item.data1_type = ASCTI_DT_LIBRARY;
       	         		item.data1 = (char*)image_name;
       	         		item.data1_len = image_name_sz;
       	         		item.data2_type = ASCTI_DT_NATIVEPTR;
       	         		item.data2 = (char*)&image_base_address;
       	         		item.data2_len = sizeof(uintptr_t);
				item.data3_type = ASCTI_DT_NATIVEINT;
				item.data3 = slide;
				message_add( &item );
		}
	}


	//
	// Copy and lowercase as we go	
	//
	int i;
	char buffer[512];
	for( i=0; i<image_name_sz; i++){
		if( image_name[i] < 'A' || image_name[i] > 'Z' ) buffer[i] = image_name[i];
		else buffer[i] = image_name[i]|0x60;
	}
	buffer[image_name_sz] = 0;

	//
	// Run through our strings
	//
	uint16_t id=0;
	uint32_t resume=0, flags=0;
	uint8_t sbuffer[256];

	int res = TFDefs_String_Lookup( &_CONFIG.defs_as, ASDEFS_SECTION_LIBS, sbuffer,
		(uint16_t)sizeof(sbuffer), &resume, &flags, &id );
	if( res != TFDEFS_FOUND ){
		ALOG("CI:ERR: asdefs not found in dylibs walk");
		error_report( ERRORBASE+__LINE__, res, 0 );
		return;
	}
	uint16_t reqlen = (sbuffer[1] << 8) + sbuffer[0];
	ASSERT(reqlen < sizeof(sbuffer));

	while( 1 ){
		res = TFDefs_String_Lookup( &_CONFIG.defs_as, ASDEFS_SECTION_LIBS, sbuffer,
			(uint16_t)sizeof(sbuffer), &resume, &flags, &id );
		if( res != TFDEFS_FOUND ) break;

		if( _CONFIG.flag_analytics_coalesce > 0 &&
			analytics_coalesce_check( _cache, CACHE_SIZE, flags, id ) == 1 ){
			continue;
		}

		if( STRSTR(buffer, (char*)sbuffer) != NULL ){
			ALOG("CI:TAG: DYLIB MATCH %s", image_name);
       	         	ASCTI_Item_t item;
			MEMSET(&item, 0, sizeof(item));
                	item.subtest = id;
                	item.data1_type = ASCTI_DT_LIBRARY;
                	item.data1 = (char*)image_name;
                	item.data1_len = image_name_sz;
			observations_item_common( ASDEFS_SECTION_LIBS, &item, flags );

			if( _CONFIG.flag_analytics_coalesce > 0 ){
				analytics_coalesce_add( _cache, CACHE_SIZE, &_cache_index, flags, id );
			}
		}
	}
}


// From http://opensource.apple.com/source/Security/Security-55471/sec/Security/Tool/codesign.c
typedef struct __BlobIndex {
	uint32_t type;					/* type of entry */
	uint32_t offset;				/* offset of entry */
} CS_BlobIndex;

typedef struct __SuperBlob {
	uint32_t magic;					/* magic number */
	uint32_t length;				/* total length of SuperBlob */
	uint32_t count;					/* number of index entries following */
	CS_BlobIndex index[];			/* (count) entries */
	/* followed by Blobs in no particular order as indicated by offsets in index */
} CS_SuperBlob;

#define CSMAGIC_EMBEDDED_SIGNATURE 0xfade0cc0
#define CSMAGIC_SIGNED_DATA	0xfade0b01

__attribute__((always_inline))
static inline void _lc_code_sig( uint8_t *lc_code_signature, uint32_t lc_code_signature_len )
{
	int signer_found = 0;
	ASCTI_Item_t item;

	uint32_t *u32 = (uint32_t*)lc_code_signature;

	CS_SuperBlob *sb = (CS_SuperBlob*)lc_code_signature;
	if( ntohl(sb->magic) != CSMAGIC_EMBEDDED_SIGNATURE ){
		error_report( ERRORBASE+__LINE__, 0, 0 );
		goto corrupted;
	}

	int found_signeddata = 0;
	uint32_t count;
	for( count=0; count < ntohl(sb->count); count++ ){
		uint32_t offset = ntohl(sb->index[count].offset);
		uint8_t *bytes = lc_code_signature + offset;
		uint32_t magic = ntohl(*(uint32_t*)bytes);
		uint32_t length = ntohl(*(uint32_t*)(bytes+4));

		//
		// NOTE: we are hitting some weird situations where there is
		// a SignedData section of 40 bytes, but it's not PKCS7
		// (obviously, too small). Not sure what it is, but it's not
		// even ASN1.  So be sure to skip over it.
		//
		if( magic == CSMAGIC_SIGNED_DATA  && length > 40 ){
			found_signeddata++;

#define MAX_SIGNERS 4
			TFS_SignerInfo_t signers[MAX_SIGNERS];
			int ret = TFS_PKCS7_Parse( (bytes+8), (length-8), signers, 4 );
			//ALOG("TFS_PKCS7_RET %d", ret);

			if( ret == TFS_PKCS7_ERR_MAXSIGNERS ){
				// This is a self-induced error, there were more than MAX_SIGNERS.
				error_report( ERRORBASE+__LINE__, 0, 0 );
				// NOTE: we still have 4 valid signers, so just keep going
			}
			else if( ret != TFS_PKCS7_ERR_OK ){
				ALOG("SIGNER PKCS7 ERR %d", ret);
				goto corrupted;
			}

			// Process the signer(s)
        		uint8_t digest[TCL_SHA256_DIGEST_SIZE];
			int i;
			for( i=0; i<MAX_SIGNERS; i++){
					if( signers[i].cert == NULL ) break;
					ALOG("CI:TAG: SIGNER found");

					// Let us know if more than one signer is found
					if( i == 1 ) error_report(ERRORBASE+__LINE__,0,0);

					// Hash the cert bytes
					TCL_SHA256( signers[i].cert, signers[i].cert_len, digest );

					// Report the signer
					ctiitem_setup_app( &item );
					item.test = CTI_TEST_APPLICATIONSIGNER;
					item.data1 = digest;
					item.data1_type = ASCTI_DT_HASHSHA256;
					item.data1_len = sizeof(digest);

					uint8_t subj[512];
					if( TFS_PKCS7_X509_Parse( signers[i].cert, signers[i].cert_len, NULL, 0, (char*)subj, NULL ) == 0 ){
						item.data2 = subj;
						item.data2_len = STRLEN((const char*)subj);
						item.data2_type = ASCTI_DT_X509S;
						ALOG("CI:TAG: SIGNER subject: %s", item.data2);
					}

					if( i == 0 && _CONFIG.laststart.signer1 == (*u32) && _CONFIG.flag_analytics_coalesce > 0 ){
						item.flag_no_send = 1;
					}
					if( i == 0 ) _CONFIG.laststart.signer1 = *u32;

					message_add( &item );
					signer_found++;

			} // for signers

		} // if CSMAGIC_SIGNED_DATA

	} // blob for loop

	if( found_signeddata > 0 ) goto finish;
	// SignedData not found, so fall through to corrupted

corrupted:
	ALOG("CI:ERR: SIGNER corrupted");
	ctiitem_setup_app( &item );
	item.test = CTI_TEST_APPLICATIONTAMPERINGDETECTED;
	item.subtest = 48; // Codesign blob is corrupted/invalid
	message_add( &item );

finish:
	if( signer_found == 0 ){
		ALOG("CI:WARN: SIGNER not found");
		ctiitem_setup_app( &item );
		item.test = CTI_TEST_APPLICATIONUNSIGNED;
		message_add( &item );
	}
}


#define FLAG_CRYPTO_0	1
#define FLAG_CRYPTO_1	2
#define FLAG_CODESIG	4

__attribute__((always_inline))
static inline void _self_assess( const char *fname, const struct mach_header *mh )
{
	uintptr_t lc_cursor = (uintptr_t)mh + _image_header_size(mh);
	ASCTI_Item_t item;
	
	uint32_t cflags = 0;
	for (uint32_t idx = 0; idx < mh->ncmds; idx++) {
		struct load_command *lc = (struct load_command *)lc_cursor;

		// based on https://github.com/Shmoopi/AntiPiracy/blob/master/SFAntiPiracy.m#L202
		if (lc->cmd == LC_ENCRYPTION_INFO) {
			// NOTE: there is a 32 & 64 bit version of this cmd struct; however, for the
			// parts we are accessing, they are identical. So we just use the 32 bit version.
			struct encryption_info_command *crypt_cmd = (struct encryption_info_command *)lc;
			cflags = (cflags) | (crypt_cmd->cryptid < 1) ? FLAG_CRYPTO_0 : FLAG_CRYPTO_1;
		}

		// based on http://opensource.apple.com/source/Security/Security-55471/sec/Security/Tool/codesign.c
		else if(lc->cmd == LC_CODE_SIGNATURE) {

			struct linkedit_data_command *cs_cmd = (struct linkedit_data_command *)lc;
			//uintptr_t csblob = (uintptr_t)mh + cs_cmd->dataoff;
			//uint32_t csblob_sz = cs_cmd->datasize;

			// Mark it as a code sig was seen (but doesn't mean it's valid)
			cflags |= FLAG_CODESIG;

			// Tricky: we use the offset we load from the in-mem LC_CODE_SIG command,
			// but those offsets are file-based.  To prevent searching for where the non-executable
			// memory got loaded, we will instead just load the signature directly from the 
			// executable file, using these already-discovered offsets.  If things don't align,
			// then flags will be thrown and it will be treated as a problematic signature.		
			int res = _load_cs_from_executable(fname, mh, cs_cmd->dataoff, cs_cmd->datasize);
			if( res != 0 ){
				error_report( ERRORBASE+__LINE__, res, 0 );

				// basically, there was an error in trying to get the codesign blob from the
				// executable. We are going to call this an internal integrity error.
				// NOT-MVP-TODO: characterize this better
				ctiitem_setup_app( &item );
				item.test = CTI_TEST_APPLICATIONTAMPERINGDETECTED;
				item.subtest = _SUBTEST_INTERNAL_INTEGRITY;
				item.data3_type = ASCTI_DT_VRID;
				item.data3 = ERRORBASE+__LINE__;
				message_add( &item );
			}
		}
		lc_cursor += lc->cmdsize;
	}

/////////////////////////////////////////////////////////////////////////////////////////////////
	
	if( (cflags & FLAG_CRYPTO_0) ){
		ALOG("CI:TAG: IPA ENCRYPTION DISABLED");
		ctiitem_setup_app( &item );
		item.test = CTI_TEST_APPLICATIONENCRYPTIONDISABLED;
		message_add( &item );
	}
 	else if( (cflags & (FLAG_CRYPTO_0|FLAG_CRYPTO_1))==0 ){
		ALOG("CI:TAG: IPA ENCRYPTION MISSING");
		ctiitem_setup_app( &item );
		item.test = CTI_TEST_APPLICATIONUNENCRYPTED;
		message_add( &item );
	}

	if( (cflags & FLAG_CODESIG) == 0 ){
		ALOG("CI:TAG: IPA UNSIGNED");
		ctiitem_setup_app( &item );
		item.test = CTI_TEST_APPLICATIONUNSIGNED;
		message_add( &item );
	}

// License/Pro feature:
#if 0
	// figure out the total region size for hashing
	// http://stackoverflow.com/questions/9198385/on-os-x-how-do-you-find-out-the-current-memory-protection-level
	vm_size_t vmsize;
	vm_address_t address = (vm_address_t)mh;
	vm_region_basic_info_data_t info;
	mach_msg_type_number_t info_count = VM_REGION_BASIC_INFO_COUNT;
	memory_object_name_t object;

#ifdef __aarch64__
	kern_return_t status = vm_region_64( mach_task_self(), &address, &vmsize,
		VM_REGION_BASIC_INFO, (vm_region_info_t)&info, &info_count, &object );
#else
	kern_return_t status = vm_region( mach_task_self(), &address, &vmsize,
		VM_REGION_BASIC_INFO, (vm_region_info_t)&info, &info_count, &object );
#endif
	if( status ){
		ALOG("CI:ERR: vmregion of self");
		// NOT-MVP-TODO: SEF/SOP?
		error_report( ERRORBASE+__LINE__, 0, 0 );
	} else {
		ALOG("CI:TAG: SELF start=%p len=%lx (mh=%p)", (void*)address, (long)vmsize, mh);

		TCL_SHA256( (const uint8_t*)address, (size_t)vmsize, digest );

		ctiitem_setup_app( &item );
		item.test = CTI_TEST_APPLICATIONMEASUREMENT;
		item.subtest = _SUBTEST_APPMEASURE_IMAGE;
		item.data1 = digest;
		item.data1_type = ASCTI_DT_HASHSHA256;
		item.data1_len = TCL_SHA256_DIGEST_SIZE;

		if( _CONFIG.laststart.measure3 ==(*u32) && _CONFIG.flag_analytics_coalesce > 0 )
			item.flag_no_send = 1;
		else
			_CONFIG.laststart.measure3 = *u32;

		message_add( &item );
	}
#endif
/////////////////////////////////////////////////////////////////////////////////////////////////

}


void observations_dylibs()
{
	// We need to look up ourselves
	Dl_info image_info;
	if( dladdr(observations_dylibs, &image_info) == 0 || image_info.dli_fname == NULL || image_info.dli_fname[0] == 0 ){
		// Failure
		error_report( ERRORBASE+__LINE__, 0, 0 );
		ASCTI_Item_t item;
		MEMSET(&item, 0, sizeof(item));
		item.test = CTI_TEST_APPLICATIONTAMPERINGDETECTED;
		item.subtest = _SUBTEST_INTERNAL_INTEGRITY;
		item.data3_type = ASCTI_DT_VRID;
		item.data3 = ERRORBASE+__LINE__;
		message_add( &item );

	} else {
		ALOG("CI:TAG: EXE PATH: %s", image_info.dli_fname);
		_self_assess( image_info.dli_fname, (const struct mach_header*)image_info.dli_fbase );
	}

	_dyld_register_func_for_add_image( _image_callback );
}

void observations_dylibs_sync()
{
	unsigned int cnt = 0;
	const char ** (*cin)(unsigned int *);
	// TODO: obfuscate this string:
	cin = dlsym(RTLD_DEFAULT, "objc_copyImageNames");
	if( cin == NULL ){
		error_report( ERRORBASE+__LINE__, 0, 0 );
		ASCTI_Item_t item;
		MEMSET(&item, 0, sizeof(item));
		item.test = CTI_TEST_APPLICATIONTAMPERINGDETECTED;
		item.subtest = _SUBTEST_INTERNAL_INTEGRITY;
		item.data3_type = ASCTI_DT_VRID;
		item.data3 = ERRORBASE+__LINE__;
		message_add( &item );
		return;

	}
	const char **names = (*cin)(&cnt);

	if( names != NULL ){
		unsigned int i;
		for( i=0; i<cnt; i++){
			//ALOG("CI:TAG: dylib=%s", names[i]);
			// TODO
		}
		free(names);
	}
}

