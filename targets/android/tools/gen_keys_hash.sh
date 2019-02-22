#!/bin/sh

ASCRYPTO_DIR=/opt/as/as_crypto/release/linux/
ASCLIB=${ASCRYPTO_DIR}/lib/libaddsec_crypto_host.a

gcc -o /tmp/gkh -I../jni/ -I${ASCRYPTO_DIR}/include/  gen_keys_hash.c ${ASCLIB}
/tmp/gkh
rm /tmp/gkh
