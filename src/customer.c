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

#include "as_mobileawareness.h"
#include "as_ma_private.h"
#include "ascti_tests.h"

#include "tf_persist.h"

#include "observations_debugger.inline.c"

#define ERRORBASE 31000

static int _send( uint16_t typ, uint32_t test, uint32_t subtest, uint16_t dtype, const char *data )
{
        ASCTI_Item_t item;
        MEMSET( &item, 0, sizeof(item) );
	item.type = typ;
	item.test = test;
	item.subtest = subtest;

	if( data != NULL ){
        	item.data1_type = dtype;
		item.data1_len = STRLEN(data);
		item.data1 = (void*)data;
	}

	if( message_add( &item ) != 0 ) return AS_ERR_GENERAL;
	return AS_SUCCESS;
}

void customer_login_status( const int status )
{
	// Confirm order of operations
	if( _CONFIG.flag_configured == 0 || _CONFIG.flag_messaging_network == 0 ) return;

	// Send outward
	_send( ASCTI_OBT_CUST, status == 0 ? CTI_TEST_LOGINUNSUCCESSFUL : CTI_TEST_LOGINSUCCESSFUL,
		0, 0, NULL );

	// Force flush failure messages
	if( status == 0 ) messages_flush();
}

int customer_message( const uint32_t id, const char *data )
{
	// Confirm order of operations & that we can send messages
	if( _CONFIG.flag_configured == 0 ) return AS_ERR_GENERAL;
	if( _CONFIG.flag_messaging == 0 ) return AS_ERR_GENERAL;

	if( data == NULL ) return AS_ERR_GENERAL;
	// Enforce a limit
	// TODO: increase this limit, and document it:
	if( STRLEN(data) > 4096 ) return AS_ERR_GENERAL;

	// Send outward
	if( _send( ASCTI_OBT_CUST, CTI_TEST_CUSTOMERMESSAGE, id, ASCTI_DT_STRING, data ) != 0 )
		return AS_ERR_GENERAL;
	return AS_SUCCESS;
}

int customer_identity( const char *data )
{
	// Confirm order of operations
	if( _CONFIG.flag_configured == 0 ) return AS_ERR_GENERAL;

	// Sanity check the length
	// TODO: document this length limit
	size_t s = STRLEN(data)+1; // +1 for NULL
	if( s > sizeof(_CONFIG.user2) ) return AS_ERR_GENERAL;

	// Save it to our configs
	MEMCPY( _CONFIG.user2, data, s );
	_CONFIG.flag_has_user2 = 1;
	_CONFIG.cti_config.user2 = _CONFIG.user2;

	// Persisting is best effort
	uint32_t len = s;
	if( _CONFIG.flag_disable_user2_persist == 0 ){
		if( TFP_Set_Ex((uint8_t*)_P_ID2, _CONFIG.cpath, (uint8_t*)data, s, _CONFIG.id_sys1,
				ASMA_SYSID_MAX, _CONFIG.pkg) != TFP_OK )
			error_report(ERRORBASE+__LINE__, 0, 0);
	}

	// Message it outwards
	if( _CONFIG.flag_messaging ){
		if( _send( ASCTI_OBT_APP, CTI_TEST_IDENTITYREGISTRATION, 0,
			ASCTI_DT_USERNAME, data ) == 0 )
			messages_flush();
	}

	return AS_SUCCESS;
}

void customer_reachability()
{
	observations_debugger(0, &_CONFIG.track_debug);
	messages_flush();
}
