#!/bin/sh

RELEASE_DIR=../../build/release/android/
INTERNAL_DIR=../../build/internal/android/
LIBNOM=libasma
MODNOM=asma

JAVAOUT=java/MobileAwareness/asma/build/outputs/aar/

echo ======================================================
echo ASMA PACKAGE: Begin
echo ======================================================

if [ ! -e "${INTERNAL_DIR}/RELEASE.defs" ]; then
	echo "ERROR: build defs"
	exit 1
fi

if [ ! -e "${JAVAOUT}/asma-standalone.aar" ]; then
	echo "ERROR: Build asma-standalone.aar"
	exit 1
fi

if [ ! -e "${JAVAOUT}/asma-embedded.aar" ]; then
	echo "ERROR: Build asma-embedded.aar"
	exit 1
fi

mkdir -p ${RELEASE_DIR}/standalone/java/
cp ${JAVAOUT}/asma-standalone.aar /tmp/asma.aar
if [[ $? -ne 0 ]]; then
	exit 1
fi

unzip /tmp/asma.aar -d /tmp/ classes.jar
cp /tmp/classes.jar ${RELEASE_DIR}/standalone/java/asma-standalone.jar
if [[ $? -ne 0 ]]; then
	exit 1
fi

rm -f /tmp/classes.jar /tmp/asma.aar

mkdir -p ${RELEASE_DIR}/embeddable/java/
cp ${JAVAOUT}/asma-embedded.aar /tmp/asma.aar
if [[ $? -ne 0 ]]; then
	exit 1
fi

unzip /tmp/asma.aar -d /tmp/ classes.jar
cp /tmp/classes.jar ${RELEASE_DIR}/embeddable/java/asma-embedded.jar
if [[ $? -ne 0 ]]; then
	exit 1
fi

rm -f /tmp/classes.jar /tmp/asma.aar

mkdir -p ${RELEASE_DIR}/assets/
cp ${INTERNAL_DIR}/RELEASE.defs ${RELEASE_DIR}/assets/as.def
if [[ $? -ne 0 ]]; then
	exit 1
fi

mv ${RELEASE_DIR}/standalone/lib ${RELEASE_DIR}/standalone/jniLibs
mv ${RELEASE_DIR}/embeddable/lib ${RELEASE_DIR}/embeddable/libs_mbedtls_internal

mkdir ${RELEASE_DIR}/examples/
cp examples/* ${RELEASE_DIR}/examples/

echo ======================================================
echo ASMA PACKAGE: Finish
echo ======================================================
