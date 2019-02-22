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

#ifndef _ANALYTICS_PLATFORM_INLINE_C_
#define _ANALYTICS_PLATFORM_INLINE_C_

#include "as_cti.h"
#include "ascti_tests.h"

//
// NOTE: this is technically not "thread safe" regarding the check & update of
// the _rooted variable.  Worse case scenario, we will get duplicate root
// detected messages if we have thread race conditions.  It's acceptable,
// we don't need to put locks around it.
//
static int _rooted = 0;

void analytics_platform( ASCTI_Item_t *item )
{

	// We need to aggregate signs of root, and decide if it's rooted or not
	if( _rooted > 0 ) return;

	// AV subtests overlap the isolated CTI subtests for other stuff, so we need
	// to exempt those.
	if( item->test == CTI_TEST_ANTIVIRUSINSTALLED ) return;

	if( item->test == CTI_TEST_SYSTEMROOTJAILBREAK ){
		// decided externally; just record the result
		_rooted++;
		return;
	}


	// Some various things that are root indicators
	if( (item->test == CTI_TEST_PRIVILEGEPROVIDINGAPPLICATIONINSTALLED) ||  // su or something
		(item->subtest == 9) || // substrate
		(item->subtest == 7) || // misc rooted file
		(item->subtest == 14) || // misc rooting app
		(item->subtest == 73) || // xpose framework
		(item->subtest == 71) || // framaroot
		(item->subtest == 75) || // /root hiding/anti-jailbreak detection
		(item->subtest == 79) || // baidu root
		(item->subtest == 80) || // kingo root
		(item->subtest == 81)  // pingpong root
		)
	{
		// Looks like it's rooted
		_rooted++;
		ASCTI_Item_t item;
		MEMSET(&item, 0, sizeof(item));
		item.test = CTI_TEST_SYSTEMROOTJAILBREAK;
		message_add( &item );

		// NOT-MVP-TODO laststart save the rooted value?  if it was rooted then,
		// and not rooted now, they either found a way to fake around it or unrooted.
		// Technically the historical SIEM record should track the different rooting
		// statuses between invokes, so we don't have to solve this right now.
	}
}

#endif
