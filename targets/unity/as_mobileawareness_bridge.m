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

#import "as_mobileawareness.h"
#import <Foundation/Foundation.h>

int AS_MobileAwareness_Unity_Init_Bridge( uint8_t *c, uint32_t csz, uint8_t *d, uint32_t dsz,
	void(*cb)(int,int,uint8_t*,uint32_t,uint8_t*,uint32_t) )
{
	AS_UUID_DEFAULT_IDFV(devid);
	return AS_Initialize_Unity( devid, c, csz, d, dsz, cb );
}
