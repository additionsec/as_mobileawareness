#include <CoreFoundation/CoreFoundation.h>
#include <CFNetwork/CFNetwork.h>
#include <objc/runtime.h>
#include <objc/message.h>
#include <arpa/inet.h>

#include "observations/checkhook.h"

#include "as_ma_private.h"
#include "tf_netsec.h"
#include "ascti_tests.h"

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


// Based on:
// http://stackoverflow.com/questions/8798699/i-can-get-the-system-proxy-with-objective-c-code-but-i-want-to-write-it-with-c

#define ERRORBASE	39000

///////////////////////////////////////////////////
// Obfuscated strings
//

#define WORK_MAX	3

static const uint32_t HTTP[] = {0x22d9a184,0x79877de0,}; // "http://"
static const uint32_t HTTPS[] = {0x22d9a184,0x568768a9,0x1fa97f4,}; // "https://"

#define _STR_START      0x52add5ec
#define _S(nom) _decode((sizeof(nom)/4)-1,nom,work)


///////////////////////////////////////////////////

int proxy_setup( TFN_WebRequest_t *req, int report )
{
	int res = 0, port = 0;
	struct sockaddr_in proxy_addr;
	CFURLRef urlRef = NULL;
	CFDictionaryRef proxyDicRef = NULL;
	CFDictionaryRef defProxyDic = NULL;
	CFArrayRef urlProxArrayRef = NULL;
	CFStringRef hostNameRef = NULL;
	CFNumberRef portNumberRef = NULL;

	uint32_t work[WORK_MAX]; // For string decoding

	int found = 0, record;
	CHECK_HOOK(CFNetworkCopySystemProxySettings, found, record);
	CHECK_HOOK(CFURLCreateWithBytes, found, record);
	CHECK_HOOK(CFNetworkCopyProxiesForURL, found, record);
	CHECK_HOOK(TFN_DNS_Lookup, found, record);
	REPORT_HOOKING(found, record);

	char buffer[TFN_MAX_HOSTNAME + 8 + 6 + 1]; // + "https://" + ":XXXXX/"
	buffer[0] = 0;
	char *ptr = buffer;

	proxyDicRef = CFNetworkCopySystemProxySettings();
	if (!proxyDicRef){
		if(report) error_report(ERRORBASE+__LINE__,0,0);
		goto done;
	}

	CFIndex cnt = CFDictionaryGetCount( proxyDicRef );
	if( cnt == 0 ) {
		// No proxies defined, we are done
		goto done;
	}

	// Have to create a URL for the given destination
	MEMSET(buffer, 0, sizeof(buffer));
	if( (req->flags & TFN_WEBREQUEST_FLAG_SSL) > 0 ){
		MEMCPY( ptr, _S(HTTPS), 8); 
		ptr += 8;
	} else {
		MEMCPY( ptr, _S(HTTP), 7); 
		ptr += 7;
	}
	MEMCPY( ptr, req->hostname, STRLEN(req->hostname) );
	ptr += STRLEN(req->hostname);
	*ptr = ':'; ptr++;
	ptr += ITOA(req->port, ptr);

	ALOG("CI:TAG: URL to proxy: '%s'", buffer);

	urlRef = CFURLCreateWithBytes( NULL, (uint8_t*)buffer, STRLEN(buffer), kCFStringEncodingASCII, NULL );
	if (!urlRef){
		if(report) error_report(ERRORBASE+__LINE__,0,0);
		goto done;
	}

	urlProxArrayRef = CFNetworkCopyProxiesForURL(urlRef, proxyDicRef);
	if (!urlProxArrayRef){
		if(report) error_report(ERRORBASE+__LINE__,0,0);
		goto done;
	}
	cnt = CFArrayGetCount( urlProxArrayRef );
	if( cnt == 0 ) goto done;

	// NOTE: we only use the first proxy, which is also supposed to be the optimal proxy.
	// We also don't support proxy autoconfiguration (CFNetworkCopyProxiesForAutoConfigurationScript)

	defProxyDic = (CFDictionaryRef)CFArrayGetValueAtIndex(urlProxArrayRef, 0);
	if (!defProxyDic){
		if(report) error_report(ERRORBASE+__LINE__,0,0);
		goto done;
	}

	// NOTE: IOS doesn't seem to support HTTPS proxies, just HTTP proxies

	portNumberRef = (CFNumberRef)CFDictionaryGetValue(defProxyDic, (const void*)kCFProxyPortNumberKey);
	if (!portNumberRef){
		//if(report) error_report(ERRORBASE+__LINE__,0,0);
		goto done;
	}
	if (!CFNumberGetValue(portNumberRef, kCFNumberSInt32Type, &port)){
		if(report) error_report(ERRORBASE+__LINE__,0,0);
		goto done;
	}

	hostNameRef = (CFStringRef)CFDictionaryGetValue(defProxyDic, (const void*)kCFProxyHostNameKey);
	if (!hostNameRef){
		//if(report) error_report(ERRORBASE+__LINE__,0,0);
		goto done;
	}

	// TODO: check string length, err early if bigger than buffer

	if (!CFStringGetCString(hostNameRef, buffer, sizeof(buffer), kCFStringEncodingASCII)) {
		if(report) error_report(ERRORBASE+__LINE__,0,0);
		goto done;
	}

	ALOG("CI:TAG: Proxy found host=%s port=%d", buffer, port);
	ASCTI_Item_t item;
	MEMSET(&item, 0, sizeof(item));
	item.test = CTI_TEST_PROXYCONFIGURED;
	item.data1_type = ASCTI_DT_HOSTNAME;
	item.data1_len = STRLEN(buffer);
	item.data1 = buffer;
	item.data3_type = ASCTI_DT_PORT;
	item.data3 = port;
	message_add( &item );

	if( TFN_DNS_Lookup( buffer, port, &proxy_addr ) == 0 && proxy_addr.sin_port > 0 ){
		// Set up the proxy into the req
		req->flags |= TFN_WEBREQUEST_FLAG_PROXY;
		MEMCPY( &req->destination, &proxy_addr, sizeof(proxy_addr) );
		res = 1;
	} else {
		// TODO: report error? report a "proxy configured but lookup failed?"
		// Fall through to just going direct
	}

done:
	if (urlProxArrayRef) CFRelease(urlProxArrayRef); 
	if (proxyDicRef) CFRelease(proxyDicRef); 
	if (urlRef) CFRelease(urlRef);

	ALOG("CI:TAG: Proxy check result=%d", res);
	return res;
}
