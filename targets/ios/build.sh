#!/bin/sh

RELEASE_DIR=../../build/release/ios/
INTERNAL_DIR=../../build/internal/ios/
LIBNOM=libasma
MODNOM=asma

./build2.sh
[ $? -eq 0 ] || exit $?

rm -rf ${RELEASE_DIR}/lib
rm -rf ${RELEASE_DIR}/include
mkdir -p ${RELEASE_DIR}/lib/
mkdir -p ${RELEASE_DIR}/include/

cp build/include/* ${RELEASE_DIR}/include/
cp build/lib/${LIBNOM}.a ${RELEASE_DIR}/lib/

exit 0

ARCH=armv7
mkdir -p ${INTERNAL_DIR}/lib/${ARCH}/
cp build/lib/${LIBNOM}_${ARCH}.a* ${INTERNAL_DIR}/lib/${ARCH}/
mkdir -p ${INTERNAL_DIR}/obj/${ARCH}/${MODNOM}/
cp -r build/obj_${ARCH}/* ${INTERNAL_DIR}/obj/${ARCH}/${MODNOM}/

ARCH=armv7s
mkdir -p ${INTERNAL_DIR}/lib/${ARCH}/
cp build/lib/${LIBNOM}_${ARCH}.a* ${INTERNAL_DIR}/lib/${ARCH}/
mkdir -p ${INTERNAL_DIR}/obj/${ARCH}/${MODNOM}/
cp -r build/obj_${ARCH}/* ${INTERNAL_DIR}/obj/${ARCH}/${MODNOM}/

ARCH=arm64
mkdir -p ${INTERNAL_DIR}/lib/${ARCH}/
cp build/lib/${LIBNOM}_${ARCH}.a* ${INTERNAL_DIR}/lib/${ARCH}/
mkdir -p ${INTERNAL_DIR}/obj/${ARCH}/${MODNOM}/
cp -r build/obj_${ARCH}/* ${INTERNAL_DIR}/obj/${ARCH}/${MODNOM}/

ARCH=i386
mkdir -p ${INTERNAL_DIR}/lib/${ARCH}/
cp build/lib/${LIBNOM}_${ARCH}.a* ${INTERNAL_DIR}/lib/${ARCH}/
mkdir -p ${INTERNAL_DIR}/obj/${ARCH}/${MODNOM}/
cp -r build/obj_${ARCH}/* ${INTERNAL_DIR}/obj/${ARCH}/${MODNOM}/

ARCH=x86_64
mkdir -p ${INTERNAL_DIR}/lib/${ARCH}/
cp build/lib/${LIBNOM}_${ARCH}.a* ${INTERNAL_DIR}/lib/${ARCH}/
mkdir -p ${INTERNAL_DIR}/obj/${ARCH}/${MODNOM}/
cp -r build/obj_${ARCH}/* ${INTERNAL_DIR}/obj/${ARCH}/${MODNOM}/

