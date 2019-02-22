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

#include <errno.h>
#include <pthread.h>
#include <sys/time.h>

#include "as_ma_private.h"
#include "as_cti.h"
#include "ascti_tests.h"

#include "tf_netsec.h"
//#include "tf_qf.h"
#include "tf_cal.h"
#include "tf_tlv.h"


#define ERRORBASE		33000

#define MEM_Q_SIZE		(1024 * 256)
#define REPORT_MEM_SIZE		(1024 * 64)
#define ITEMS_SIZE		64
#define ITEM_HEADER_SIZE	8
#define TIMEOUT			20000

#define TAG_PINS        7

static void *_message_send_thread_handler( void *arg );

static pthread_cond_t _signal_send = PTHREAD_COND_INITIALIZER;
static pthread_t _message_sender_thread;
static int _initialized = 0;


#define WORK_MAX	8

static const uint32_t APPLICATIONOCTETSTREAM[] = {0x3edda58d,0x11cd35ba,0x69dea58e,0x5fd33dbd,0x64c5f792,0x42c571ba,0x5a89ee3,}; // "application/octet-stream"

#define _STR_START      0x52add5ec
#define _S(nom) _decode((sizeof(nom)/4)-1,nom,work)


int messages_init()
{
	if( _initialized != 0 ){ ALOG("CI:ERR: message_init more than once"); return -1; }
	if( _CONFIG.flag_configured == 0 ){ ALOG("CI:ERR: need to configure before message_init"); return -1; }
	_initialized = 1;


	//
	// Init our memory-based queue
	//
	uint8_t qres = TFTLV_Init_Mem( &_CONFIG.mqA, MEM_Q_SIZE );
	if( qres != TFTLV_RET_OK ){
		return error_report(ERRORBASE+__LINE__,qres,-1);
	}


	// Even if we fail to set up the network part, we can do messaging in callback-only mode.
	// Which means message_init() can fail, but it will still allow messages to the 
	// callback thru.
	_CONFIG.flag_messaging = 1;

	if( _CONFIG.req_messages.hostname[0] == 0 ){
		ALOG("CI:TAG: No url_message host set, doing local-only messages");
		_CONFIG.flag_messaging_network = 0;
		return 0;
	}


	//
	// Calculate queue file path
	//
	uint8_t path[ ASMA_PATH_MAX + 16 ] = {0};
	int pathlen = (int)STRLEN((char*)_CONFIG.cpath);
	MEMCPY( path, _CONFIG.cpath, pathlen + 1 );
	path[pathlen] = '/';
	path[pathlen+1] = 0;
	MKDIR((char *)path,0700);

	//
	// Create our queue file
	//
	MEMCPY(&path[pathlen + 1], _F_MSG_FQA, STRLEN(_F_MSG_FQA)+1);
	ALOG("CI:TAG: qfa path=%s", path);

	int tries = 2;
	while( tries-- > 0 ){
		qres = TFTLV_Init_ProtectedFile( &_CONFIG.fqA, (char*)path, _CONFIG.id_sys1 );
		if( qres == TFTLV_RET_OK ) break;
		else if( qres == TFTLV_RET_WRONGKEY ){
			ALOG("CI:ERR: qfA wrong key");
			// TODO
		}
		else if( qres == TFTLV_RET_INTEGRITY ){
			ALOG("CI:ERR: qfA integrity violation");

			ASCTI_Item_t item;
			MEMSET(&item, 0, sizeof(item));
			item.test = CTI_TEST_APPLICATIONTAMPERINGDETECTED;
			item.subtest = _SUBTEST_INTERNAL_QFSIG;
			item.data3_type = ASCTI_DT_VRID;
			item.data3 = ERRORBASE+__LINE__;
			message_add( &item );

			// Fall thru, on purpose
		} else {
			// NOT-MVP-TODO: inform the app of possible message purging?
		}

		// Other errors are just handled
		ALOG("CI:ERR: Failed to open qfA; res=%d", qres);

		// Delete the file, so we can create a fresh one
		UNLINK((char*)path);

		// Since we are deleting the QF, any prior items may never be sent.  So
		// wipe laststart so everything is resent fresh.
		MEMSET( &_CONFIG.laststart, 0, sizeof(_CONFIG.laststart) );
	}

	// Did we open a valid file?
	if( qres != TFTLV_RET_OK ){
		return error_report(ERRORBASE+__LINE__,qres,-1);
	}

	// Create our message sending thread
	pthread_attr_t attr;
	if( pthread_attr_init( &attr ) != 0 ){ ALOG("CI:ERR: Failed to attr_init"); return -1; }
	if( pthread_attr_setdetachstate( &attr, PTHREAD_CREATE_DETACHED ) != 0 ){
		ALOG("CI:ERR: Failed to set detached"); 
		return error_report(ERRORBASE+__LINE__,0,-1); }
	if( pthread_create( &_message_sender_thread, &attr, 
		_message_send_thread_handler, NULL ) != 0 ){
		ALOG("CI:ERR: Failed to create sender thread"); 
		return error_report(ERRORBASE+__LINE__,0,-1); }


	_CONFIG.flag_messaging_network = 1;
	return 0;
}

int message_add( ASCTI_Item_t *item ) 
{
	ASSERT( item );
	ASSERT( item->test );
	ALOG("CI:MSG: Adding message test=%d subtest=%d flns=%d", item->test, item->subtest, item->flag_no_send);
	analytics_posture_contribution( item );

	if( _CONFIG.flag_configured == 0 ){
		ALOG("CI:ERR: message_add before configured!");
		return -1;
	}

	// Bail if messaging isn't enabled
	if( _CONFIG.flag_messaging == 0 ) return -1;

	// NOTE: when we call the callback, native code may get direct raw pointers.
	// To prevent the callback from modifying the data, we are going to make sure
	// to encode a copy first, then call the callback.  The exception is if we
	// don't need to send it, in which case we will call the callback immediately

	// Some things don't get sent to the backend
	if( item->flag_no_send || _CONFIG.flag_messaging_network == 0 ){
		// Inform the app, if desired
		if( _CONFIG.flag_cb ) _CONFIG.msg_callback( item->test, item->subtest, item );
		return 0;
	}

	// Inform the app, if desired (now that we've safely encoded the data or failed trying)
	// TODO: reduce to just item
	if( _CONFIG.flag_cb ) _CONFIG.msg_callback( item->test, item->subtest, item );

	// Encode the item - first the item body, so we know the length; then prepend
	// an item header, so it's ready to send on the wire in a protobuf report
	// TODO: purge this tmp:
	uint8_t tmp[8192], tmp2[8];
	uint32_t len = 0, len2 = 0;
	int res = ASCTI_Encode_Item( &_CONFIG.cti_config, item, &tmp[8], sizeof(tmp)-8, &len);
	if( res != 0 ){
		ALOG("CI:ERR: Failed to encode item, insz=%d outsz=%d", (int)(sizeof(tmp)), len);
		// NOT-MVP-TODO: re-encode without data? better than nothing...
		return error_report(ERRORBASE+__LINE__,len,-1);
	}

	res = ASCTI_Encode_Item_Header( len, tmp2, sizeof(tmp2), &len2 );
	if( res != 0 || len2 >= 8 ){
		ALOG("CI:ERR: Failed to encode item header");
		return error_report(ERRORBASE+__LINE__,len,-1);
	}
	uint8_t *ptr = &tmp[8 - len2];
	MEMCPY( ptr, tmp2, len2 );

	//
	// Trylock on mqA
	//
	int qres;
	int lockres = __sync_bool_compare_and_swap( &_CONFIG.mqA_lock, 0, 1 );
	__sync_synchronize();
	if( lockres ){
		// We got lock on mqA, attempt an add
		qres = TFTLV_Add_ToMem( &_CONFIG.mqA, 1, ptr, (len + len2) );

		// Unlock regardless
		__sync_synchronize();
		_CONFIG.mqA_lock = 0;

		if( qres == TFTLV_RET_OK ){
			//ALOG("CI:TAG: Pushed to mqA");
			return 0;
		}
		ALOG("CI:ERR: Failed to push to mqA, res=%d", qres);

		// If too big, don't try elsewhere, it won't work
		if( qres == TFTLV_RET_BIGMSG ){
			return error_report(ERRORBASE+__LINE__, len, -1);
		}

		// Errors other than OVERFLOW (queue is full) should be reported
		// (and we fall through to try mqB)
		else if( qres != TFTLV_RET_OVERFLOW ){
			error_report(ERRORBASE+__LINE__, qres, 0);
		}
	}


	//
	// If we get here, we could not add to mqA; now try to add to
	// the queue file 
	//
	while( !__sync_bool_compare_and_swap( &_CONFIG.fqA_lock, 0, 1 ) ){}
	__sync_synchronize();
	qres = TFTLV_Add_ToFile( &_CONFIG.fqA, 1, ptr, (len + len2) );
	__sync_synchronize();
	_CONFIG.fqA_lock = 0;

	if( qres == TFTLV_RET_OK ){
		ALOG("CI:TAG: Pushed to fqA");
		return 0;
	}
	ALOG("CI:ERR: Failed to push to fqA, res=%d dbg=%d", qres, _CONFIG.fqA.dbg);
	return error_report(ERRORBASE+__LINE__, qres, -1);
}


typedef struct {
	uint8_t hash[TCL_SHA256_DIGEST_SIZE];
	int matched;
} _pin_state_t;



static TFTLV_CALLBACK_DEF(_pincallback){
	// tag, len, data, state

	// We only care about HPKP pins
	if( tag != TAG_PINS ) return TFTLV_CB_RET_CONTINUE;

	ASSERT(state);
	_pin_state_t *st = (_pin_state_t*)state;
	// If we've already matched, we're done
	if( st->matched ) return TFTLV_CB_RET_STOP;

	// TODO: factor in hostname matching
	ASSERT(len >= 32);
	if( MEMCMP(st->hash, data, TCL_SHA256_DIGEST_SIZE) == 0 ){
		ALOG("CI:TAG: message pin matched for %s", (char*)&data[TCL_SHA256_DIGEST_SIZE]); 
		st->matched++;
		return TFTLV_CB_RET_STOP;
	}

	return TFTLV_CB_RET_CONTINUE;
}



static int _cert_callback(void *req,
	uint8_t *subject, uint32_t depth, int is_proxy,
	uint8_t *cert, uint32_t cert_len, 
	uint8_t *spki, uint32_t spki_len)
{
	ASSERT(req);
	ASSERT(cert);
	ASSERT(spki);
	ASSERT(_CONFIG.flag_configured == 1);

	// Check for known proxy subject signatures - in any of leaf or intermediates
	if( subject != NULL ){

		uint16_t id=0;
		uint32_t resume=0, flags=0;
		uint8_t buffer[ 64 ];
		int found = 0;

		int res = TFDefs_String_Lookup( &_CONFIG.defs_as, ASDEFS_SECTION_PROXY, buffer,
			(uint16_t)sizeof(buffer), &resume, &flags, &id );
		if( res != TFDEFS_FOUND ){
			ALOG("CI:ERR: unable to find proxy section in defs");
			error_report(ERRORBASE+__LINE__, res, 0);
		} else {
			uint16_t reqlen = (buffer[1] << 8) + buffer[0];
			ASSERT( reqlen < sizeof(buffer) );

			while( 1 ){
				res = TFDefs_String_Lookup( &_CONFIG.defs_as, ASDEFS_SECTION_PROXY, buffer,
					(uint16_t)sizeof(buffer), &resume, &flags, &id );
				if( res != TFDEFS_FOUND ) break;
	
				if( STRSTR((char*)subject, (char*)buffer) != NULL ){
					found = id;
					break;
				}
			}
		}

		if( found > 0 ){
			ASCTI_Item_t item;
			MEMSET(&item, 0, sizeof(item));
			item.test = CTI_TEST_MITMDETECTED;
			item.subtest = found;
			item.data1_type = ASCTI_DT_X509S;
			item.data1_len = STRLEN((char*)subject);
			item.data1 = subject;
			message_add( &item );
		}
	}

	// Always allow proxy certs
	if( is_proxy ) return TFN_CERT_ALLOW;

	_pin_state_t st;
	st.matched = 0;

	// Hash the SPKI
	TCL_SHA256( spki, spki_len, st.hash );

	// Check the SPKI against our set of pins
	int res = TFTLV_Walk_Mem( &_CONFIG.tlv_config, &_pincallback, &st );
	if( res != TFTLV_RET_OK ){
		ALOG("CI:ERR: message pin walk failed %d", res); 
		return error_report(ERRORBASE+__LINE__,res,TFN_CERT_PASS);
	}

	if( st.matched > 0 ) return TFN_CERT_ALLOW;
	// We didn't find a pin for this cert, so just pass
	return TFN_CERT_PASS;
}

static void _cert_failed_callback(void *req, int is_proxy,
	uint8_t *cert, uint32_t certlen)
{
	ASSERT(req);
	TFN_WebRequest_t *request = (TFN_WebRequest_t*)req;

	// NOTE: cert can be NULL, certlen can be 0
	ssl_violation( (char*)request->hostname, cert, certlen );
}

static int _req_transmit( TFN_WebRequest_t *req );

typedef struct {
	uint8_t *base; // Base of all mem
	uint8_t *data; // Base + report_header
	uint8_t *next;
	uint32_t max;
	uint32_t cnt : 24;
	uint32_t netfail : 1;
} _q_cb_t;

static TFTLV_CALLBACK_DEF(_qitemcb) {
	// tag, len, data, state

	uint32_t work[WORK_MAX]; // for string decode
	_q_cb_t *st = (_q_cb_t*)state;

	do {
		int flush_needed = 0;

		if( data == NULL && tag == TFTLV_CB_TAG_END ){
			// queue is at end; flush and be done
			flush_needed++;

		} else {
			// Do we have room left in current buffer?
			uintptr_t used = (uintptr_t)st->next - (uintptr_t)st->base;
			if( (used + len) >= st->max ){
				// Too full, need to flush first
				flush_needed++;

				// Special: if data == next, it means the item will
				// never fit
				if( st->data == st->next ){
					// We can't handle this item...swallowing it
					// is the only way to continue.
					return error_report(ERRORBASE+__LINE__,len,
						TFTLV_CB_RET_CONTINUE);
				}
			}
		}

		if( flush_needed > 0 ){
			// Only flush if there are items
			if( st->cnt > 0 ){
				ALOG("CI:TAG: Performing message send/flush");

				// construct request
				TFN_WebRequest_t req;
				MEMCPY( &req, &_CONFIG.req_messages, sizeof(TFN_WebRequest_t) );

				char post_[5] = {'P',0,'S',0,0};
				post_[3] = 'T';
				post_[1] = 'O';

				req.timeout_ms = TIMEOUT;
				req.request_method = post_;
				req.request_data_ctype = _S(APPLICATIONOCTETSTREAM);
				req.request_data = st->base;
				req.request_data_len = (uint32_t)((uintptr_t)st->next - (uintptr_t)st->base);

				ASCTI_Item_t item;
				ctiitem_setup_app( &item );
				item.flag_no_send = 1;

				int res = _req_transmit( &req );
				if( res == 0 ){ 
					ALOG("CI:TAG: Successfully sent report");
					item.test = CTI_TEST_MESSAGESENT;
				} else {
					ALOG("CI:TAG: Report not sent; res=%d", res);
					item.test = CTI_TEST_MESSAGEDELAYED;
					st->netfail = 1;
				}

				// Indicate to app if the message was sent
				message_add( &item );

				// If we didn't transmit successful, we abort the flush
				if( res != 0 ) return TFTLV_CB_RET_STOP;
			}

			// If we are at the end, and have successfully flushed everyting up to now,
			// then we can reset the queue
			if( data == NULL && tag == TFTLV_CB_TAG_END ) return TFTLV_CB_RET_RESET;

			// Reset our memory buffer, and loop around
			st->next = st->data;
			continue;
		}


		// Add item to current buffer
		MEMCPY( st->next, data, len );
		st->next += len;
		st->cnt++;

		// Continue onto the next item
		return TFTLV_CB_RET_CONTINUE;

	} while(1);
}

static int _flush_UNLOCKED( TFTLV_Mem_t *mq, TFTLV_File_t *fq, uint8_t *report_mem, uint32_t report_mem_len )
{
	ASSERT(report_mem);
	// NOTE: mq and/or fq may be NULL

	// Allocate our state tracking structure
	_q_cb_t st;
	MEMSET( &st, 0, sizeof(st) );
	st.base = report_mem;
	st.max = report_mem_len;

	// Encode the report header at beginning of mem
	uint32_t rh_len = 0;
	if( ASCTI_Encode_Report_Header( &_CONFIG.cti_config, st.base, st.max, &rh_len ) != ASCTI_ENCODE_SUCCESS ){
		ALOG("CI:ERR: on encode report header");
		return error_report(ERRORBASE+__LINE__,0,-1);
	}
	st.next = st.data = &st.base[rh_len];

	// Now, walk the queue and send the items out
	uint8_t qres = TFTLV_RET_OK;
	if( mq != NULL ){
		ALOG("CI:TAG: Walking mqA");
		qres = TFTLV_Walk_Mem( mq, _qitemcb, &st );
	}
	else if( fq != NULL ){
		ALOG("CI:TAG: Walking fqA");
		qres = TFTLV_Walk_File( fq, _qitemcb, &st );
	}
	if( qres == TFTLV_RET_OK ){
		// Network failure means we didn't flush
		if( st.netfail) return -1;
		return 0;
	}
	return error_report(ERRORBASE+__LINE__,qres,-1);
}


static int _req_transmit( TFN_WebRequest_t *req )
{
	req->cert_callback = _cert_callback;
	req->cert_failed_callback = _cert_failed_callback;

	uint8_t resp[512];
	req->response_data = resp;
	req->response_data_max = (uint32_t)sizeof(resp);

	int using_proxy = 0;
	if( _CONFIG.flag_disable_proxy == 0 ){
		using_proxy = proxy_setup( req, 1 );
	}
	struct sockaddr_in sin, sin2;
	if( using_proxy == 0 ){
		// Do a DNS lookup, which will give us a feel for network health
		if( TFN_DNS_Lookup2( (char*)_CONFIG.req_messages.hostname, 
			_CONFIG.req_messages.port, &sin, &sin2 ) != 0 )
		{
			ALOG("CI:WARN: Unable to look up DNS hostname");
			return -1;
		}
		ALOG("CI:TAG: DNS res1 port=0x%x host=0x%x", sin.sin_port, sin.sin_addr.s_addr);
		ALOG("CI:TAG: DNS res2 port=0x%x host=0x%x", sin2.sin_port, sin2.sin_addr.s_addr);

		TFMEMCPY( &req->destination, &sin, sizeof(struct sockaddr_in) );
	}

	int loop;
	for( loop=0; loop < 2; loop++ ){

		// Send report
		ALOG("CI:TAG: Attempting transmission %d (len=%d) [%02x,%02x]", loop, req->request_data_len,
			req->request_data[0], req->request_data[1]);
		int res = TFN_Web_Request( req );
		if( res == 0 && req->response_code == 200 ){
			ALOG("CI:TAG: Successfully transmitted request");
			return 0;
		} else {
			int errno_ = errno;
			ALOG("CI:WARN: send_messages request failed, res=%d dbg=0x%x errno=%d code=%d", 
				res, req->error_debug, errno_, req->response_code);

			if( res == TFN_ERR_PINNOTCHECKED ){
				// TODO: tampering?
				ssl_violation( (char*)req->hostname, NULL, 0 );
				// we don't retry if we know we have a pin violation
				return -1;
			}
			else if( errno_ == ETIMEDOUT ){
				// Network issue, nothign to report
			}	
			else if( res == TFN_ERR_INTERNAL  || res == TFN_ERR_PROTOCOL || res == TFN_ERR_SYSTEM ){
				error_report(ERRORBASE+__LINE__,errno,0);
				ALOG("CI:ERR: send_messages res=%d", res);
			}
			else if( res == TFN_ERR_SSLHANDSHAKE ){
				error_report(ERRORBASE+__LINE__,req->error_debug,0);
			}
			if( using_proxy > 0 ){
				// Always done
				return -1;
			}
			if( loop == 0 && sin2.sin_port > 0 ){
				// check the second address
				TFMEMCPY( &req->destination, &sin2, sizeof(struct sockaddr_in) );
				continue;
			}
			return -1;
		}
	}
	return -1;
}


static void _message_ping()
{
	// construct request
	TFN_WebRequest_t req;
	MEMCPY( &req, &_CONFIG.req_messages, sizeof(TFN_WebRequest_t) );

	req.timeout_ms = TIMEOUT;

	ASCTI_Item_t item;
	ctiitem_setup_app( &item );
	item.flag_no_send = 1;

	if( _req_transmit( &req ) == 0 ){
		ALOG("CI:TAG: successfully got ping");
		item.test = CTI_TEST_GATEWAYPINGED;
	} else {
		ALOG("CI:TAG: network ping failure");
		item.test = CTI_TEST_GATEWAYPINGDELAYED;
	}

	message_add( &item );
}

static void *_message_send_thread_handler( void *arg )
{
	int res, items;

	// allocate our work memory
	uint8_t *report_mem = (uint8_t*)MMAP( NULL, REPORT_MEM_SIZE, PROT_READ|PROT_WRITE,
		MAP_PRIVATE|MAP_ANONYMOUS, -1, 0 );
	if( report_mem == MAP_FAILED ){ 
		error_report(ERRORBASE+__LINE__,errno,0);
		ABORT();
	}

	// infinite work loop, which waits on the signal_send cond.
	// SPECIAL: we also will time out/wake up every 5 mins, and perform a flush if there
	// are items -- but we won't ping upon a timeout, just flush.
	struct timeval tv;
	struct timespec ts;
	MEMSET( &ts, 0, sizeof(ts) );

	pthread_mutex_t lock_ = PTHREAD_MUTEX_INITIALIZER;

	while(1){
		// Calculate our abstime
		while( gettimeofday( &tv, NULL ) != 0 );
		if( _CONFIG.flag_elevated_monitoring > 0 ){
			ts.tv_sec = tv.tv_sec + (60); // Add 1 min
		} else {
			ts.tv_sec = tv.tv_sec + (60 * 5); // Add 5 mins
		}

		// Wait for interval or signal
		do { res = pthread_mutex_lock( &lock_ ); } while(res != 0);
		res = pthread_cond_timedwait( &_signal_send, &lock_, &ts );
		if( res != 0 && res != ETIMEDOUT ){
			error_report(ERRORBASE+__LINE__,res,0);
			ABORT();
		}
		if( res == ETIMEDOUT ){
			ALOG("CI:TAG: flush timed interval");
		}
		else {
			ALOG("CI:TAG: message signal");
		}

		// make sure we have work to do
		items = 0;
		items += TFTLV_HasItems_Mem( &_CONFIG.mqA );
		items += TFTLV_HasItems_File( &_CONFIG.fqA );
		ALOG("CI:TAG: message items=%d", items);

		// SPECIAL: if cond_timedwait timed out, and there is no work, then we don't
		// need to flush
		if( res == ETIMEDOUT && items == 0 ) continue;
		do { res = pthread_mutex_unlock( &lock_ ); } while(res != 0);

		// Something to send, or just ping?
		if( items == 0 ){
			// No work, so just do a ping instead
			_message_ping();
			continue;
		}

		// Flush mqA
		if( TFTLV_HasItems_Mem( &_CONFIG.mqA ) ){
			ALOG("CI:TAG: Flushing mqA");

			while( !__sync_bool_compare_and_swap( &_CONFIG.mqA_lock, 0, 1 ) ){}
			__sync_synchronize();

			if( _flush_UNLOCKED( &_CONFIG.mqA, NULL, report_mem, REPORT_MEM_SIZE ) != 0 ){
				ALOG("CI:WARN: Failed to flush mqA, draining to file");
				if( TFTLV_Drain_MemToFile( &_CONFIG.mqA, &_CONFIG.fqA ) != TFTLV_RET_OK ){
					// TODO
					ALOG("CI:ERR: Failed to drain to file");
				}
			}

			__sync_synchronize();
			_CONFIG.mqA_lock = 0;
		}

		// Flush fqA
		if( TFTLV_HasItems_File( &_CONFIG.fqA) ){
			ALOG("CI:TAG: Flushing fqA");

			while( !__sync_bool_compare_and_swap( &_CONFIG.fqA_lock, 0, 1 ) ){}
			__sync_synchronize();

			// TODO - file flush
			if( _flush_UNLOCKED( NULL, &_CONFIG.fqA, report_mem, REPORT_MEM_SIZE ) != 0 ){
				ALOG("CI:WARN: Failed to flush fqA");
			}

			__sync_synchronize();
			_CONFIG.fqA_lock = 0;
		}
	}
}


void messages_flush() {
	if( _CONFIG.flag_messaging_network > 0 ){
		ALOG("CI:TAG: messages flush");
		pthread_cond_signal( &_signal_send );
	}
}
