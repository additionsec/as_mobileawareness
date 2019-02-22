#!/bin/sh

RELEASE_DIR=../../build/release/ios/
INTERNAL_DIR=../../build/internal/ios/
LIBNOM=libasma
MODNOM=asma

CRYPTOVARIANT=$1

SIGN_TOOL=../../../tfs_lib/targets/darwin/build/tools/tool_dual_sign
SIGN_KEY1=../../keys/ecc_offline_1.key.raw
SIGN_KEY2=../../keys/rsa_offline_1.key.der

if [ ! -e "${INTERNAL_DIR}/RELEASE.defs" ]; then
	echo "ERROR: build defs"
	exit 1
fi

mkdir -p ${RELEASE_DIR}/sdk_${CRYPTOVARIANT}/AdditionSecurity/
[ $? -eq 0 ] || exit $?
cp ${INTERNAL_DIR}/RELEASE.defs ${RELEASE_DIR}/sdk_${CRYPTOVARIANT}/AdditionSecurity/as.def
[ $? -eq 0 ] || exit $?
# TODO: verify signature, to confirm it's signed

mkdir -p ${RELEASE_DIR}/examples/
[ $? -eq 0 ] || exit $?
cp examples/* ${RELEASE_DIR}/examples/
[ $? -eq 0 ] || exit $?

cp ${RELEASE_DIR}/include/as_mobileawareness.h ${RELEASE_DIR}/sdk_${CRYPTOVARIANT}/AdditionSecurity/
[ $? -eq 0 ] || exit $?
cp ${RELEASE_DIR}/lib/libasma.a ${RELEASE_DIR}/sdk_${CRYPTOVARIANT}/AdditionSecurity/
[ $? -eq 0 ] || exit $?


echo ======================================================
echo PACKAGED - ${CRYPTOVARIANT}
echo ======================================================
