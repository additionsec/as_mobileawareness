
#include <stdio.h>
#include <stdint.h>

#include "as_crypto.h"

#include "keys.inline.c"

int main(void){

	uint8_t digest[ASC_MD5_DIGEST_SIZE];

	ASC_MD5_Ctx_t ctx;
	ASC_MD5_Init(&ctx);
	ASC_MD5_Update(&ctx,(uint8_t*)_KEYS, sizeof(_KEYS));
	ASC_MD5_Final(&ctx, digest);

	uint16_t *ptr = (uint16_t*)digest;
	int i;
	for(i=0; i<8; i++){
		printf("#define KEYS_HASH%d  0x%x\n", (i+1),ptr[i]);
	}

	return 0;
}
