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

#ifndef _OBSERVATIONS_H_
#define _OBSERVATIONS_H_

#define ASDEFS_ANDROID_PKGS	1
#define ASDEFS_ANDROID_FILES	2

#ifdef __cplusplus
extern "C" {
#endif

void observations_pkgs_start(void **state);
void observations_pkg( int vc, void *state, const char *pkg, const uint8_t *sig1, uint32_t sig1_len,
        const uint8_t *sig2, uint32_t sig2_len, uint8_t flags, int *is_us );
void observations_pkgs_finish( void *state);

#ifdef __cplusplus
}
#endif

#endif
