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

#include <pthread.h>
#include <time.h>
#include <errno.h>
#include <unistd.h>

int mutex_timedlock( pthread_mutex_t *mutex, struct timespec *maxwait )
{
	// Older android doesn't have timedlock, so we fake it with trylock & sleep
	// NOTE: this function only works in terms of seconds

	struct timespec curr;
	int res;

	// Now try & sleep until we get the lock or expire
	while(1){
		// Will return EBUSY if locked
		do { res = pthread_mutex_trylock( mutex ); } while( res != 0 && res != EBUSY );
		if( res == 0 ) return res;

		// We didn't get the lock; sleep
		usleep( 100000 ); // 100,000us == 100ms

		// now get current time
		res = clock_gettime( CLOCK_REALTIME, &curr );
		if( res != 0 ) return ETIMEDOUT; // fake a timeout

		// Check if we expired
		if( curr.tv_sec >= maxwait->tv_sec ) return ETIMEDOUT; // timed out

		// loop and try again
	}
}

