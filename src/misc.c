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

#include "as_ma_private.h"
#include "as_cti.h"
#include "ascti_tests.h"


//
// Centralizing some common CTI item setup patterns, to reduce code size
//
void ctiitem_setup_app( ASCTI_Item_t *item )
{
	MEMSET( item, 0, sizeof(ASCTI_Item_t) );
	//item->type = ASCTI_OBT_APP;
	//item->confidence = ASCTI_CONFIDENCE_HIGH;
}

void ctiitem_setup_sys( ASCTI_Item_t *item )
{
	MEMSET( item, 0, sizeof(ASCTI_Item_t) );
	//item->type = ASCTI_OBT_SYSTEM;
	//item->confidence = ASCTI_CONFIDENCE_HIGH;
}


//
// Our common string decode routine
//
#define _STR_START      0x52add5ec
__attribute__ ((optnone,noinline))
char *_decode( uint32_t sz, const uint32_t *in, uint32_t *work ){
#pragma nounroll
        while( sz > 0 ){
                volatile uint32_t mask = sz << 26 | sz << 18 | sz << 10 | sz;
                work[sz] = in[sz] ^ in[sz-1] ^ 0x5f75f75f ^ mask;
                sz--;
        }
        work[0] = in[0] ^ _STR_START;
        return (char*)work;
}

