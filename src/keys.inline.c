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

#ifndef _KEYS_INLINE_C_
#define _KEYS_INLINE_C_

#ifndef NDEBUG
#define _KEYS_LEN 8
#else
#define _KEYS_LEN 7
#endif

// PUBLIC RELEASE NOTE: KEYS HAVE BEEN REMOVED

//#define KEYS_ECC_ROOT_CNT 1
uint8_t KEYS_ECC_ROOT[KEYS_ECC_ROOT_CNT][64] = { 
	{0}
};

//#define KEYS_RSA_ROOT_CNT 1
uint8_t KEYS_RSA_ROOT[KEYS_RSA_ROOT_CNT][292] = { 
	{0}
};

uint8_t _KEYS[_KEYS_LEN][TFC_ED25519_PK_SIZE] = 
{
	// Offline 1 key
	{0},

	// Offline 2 key
	{0},

	// Online 1 key
	{0},

	// Online 2 key
	{0},

	// Online 3 key
	{0},

	// Online 4 key
	{0},

#ifndef NDEBUG
        // Test key
        {0},
#endif

        // Terminator - REQUIRED; ASDefs checks the first 4 chars as zero and ends iterating
        {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00}
};


// MD5 hash of KEYDATA, split into uint16_t (little endian)

#ifndef NDEBUG

// Hashes w/ test key
#define KEYS_HASH1  0xa9e2
#define KEYS_HASH2  0x1dfb
#define KEYS_HASH3  0xece6
#define KEYS_HASH4  0x8cf6
#define KEYS_HASH5  0x47f8
#define KEYS_HASH6  0x6e0d
#define KEYS_HASH7  0xc4ea
#define KEYS_HASH8  0x4721

#else

// Hashes w/out test key
#define KEYS_HASH1  0xd816
#define KEYS_HASH2  0x65ec
#define KEYS_HASH3  0x5587
#define KEYS_HASH4  0x223b
#define KEYS_HASH5  0x6ce0
#define KEYS_HASH6  0x1c6a
#define KEYS_HASH7  0x0c4a
#define KEYS_HASH8  0xa35f

#endif

#endif
