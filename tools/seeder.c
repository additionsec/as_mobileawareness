#include <stdio.h>
#include <stdlib.h>

uint32_t _SEED;
uint32_t _SEED_START;
uint32_t _MULT;
uint32_t _MOD;


#if 0
#define NOM ""
#define MULT rand()
#define MOD rand()
#else
#define NOM "3"
#define MULT 0xa5fa5af
#define MOD  0x192ef7
#endif

static uint32_t _next(){ _SEED = _SEED * _MULT; return (_SEED % _MOD); }

#define COUNT 50
uint32_t TRACK[ COUNT ];

int main(void){

	sranddev();

	while(1){
		_SEED = _SEED_START = rand();
		_MULT = MULT;
		_MOD = MOD;
		_MOD &= 0x00ffffff;

		int i, j;
		int dupv = 0;
		for( i=0; i<COUNT; i++){
			uint32_t v = _next();

			// Check if this is a previous dupe
			for( j=0; j<i; j++ ){
				if(TRACK[j] == v ){
					dupv++;
					break;
				}
			}
			if( dupv > 0 ) break;
			TRACK[i] = v;
		}

		if( dupv == 0 ) break;
	}

	printf("#ifndef _SEED_H_\n#define _SEED_H_\n\n");
	printf("#define SEED" NOM "_START 0x%x\n", _SEED_START);
	printf("#define SEED_MULT 0x%x\n", _MULT);
	printf("#define SEED_MOD 0x%x\n", _MOD);
	printf("\n");
	printf("#define _SEED_NEXT(v) ( (v=v * SEED_MULT) %% SEED_MOD )\n");
	printf("\n");

	int i;
	for( i=0; i<COUNT; i++){
		printf("#define SEED" NOM "_%d 0x%x\n", i+1, TRACK[i]);
	}
	printf("\n#endif\n");

	return 0;
}
