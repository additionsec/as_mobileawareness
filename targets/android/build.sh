#!/bin/sh

RELEASE_DIR=../../build/release/android/
INTERNAL_DIR=../../build/internal/android/
LIBNOM=libasma
MODNOM=asma

# TODO:
NDKHOST=darwin-x86_64

#ASLIB_TOOL=../../../tfs_lib/targets/darwin/build/tools/tool_ed25519_sign_aslib
ASLIB_TOOL=../../../tfs_lib/targets/darwin/build/tools/tool_ecc_sign_aslib
ASLIB_SK=../../keys/ecc_offline_1.key.raw

rm -rf ${RELEASE_DIR}
mkdir -p ${RELEASE_DIR}/standalone/lib/
mkdir -p ${RELEASE_DIR}/embeddable/lib/

HEADERS=jni/src/as_mobileawareness.h

echo ======================================================
echo ASMA BUILD: Begin
echo ======================================================


echo ======================================================
echo BUILDING: Java
echo ======================================================

cd java/MobileAwareness/

./gradlew assembleStandalone
if [[ $? -ne 0 ]]; then
	exit 1
fi
./gradlew assembleEmbedded
if [[ $? -ne 0 ]]; then
	exit 1
fi

cd ../..



embprocess()
{
	ARCH=$1
	BASE=$2
	PREF=$3
	EX=$4

	AF=`find ${BUILD_BASE}/tfs_libc/build/internal/android/obj/${ARCH}/ -name \*.o`
	BF=`find ${BUILD_BASE}/tfs_lib/build/internal/android/obj/${ARCH}/ -name \*.o`
	#CF=`find ${BUILD_BASE}/tfs_mbedtls/build/internal/android/obj/${ARCH}/ -name \*.o`
	#CF=`find ${BUILD_BASE}/boringssl/build/internal/android/${ARCH}/ssl/CMakeFiles/ssl.dir/ -name \*.o`
	#DF=`find ${BUILD_BASE}/boringssl/build/internal/android/${ARCH}/crypto/CMakeFiles/crypto.dir/ -name \*.o`
	CF=${BUILD_BASE}/boringssl/build/internal/android/${ARCH}/libcrypto.a
	DF=${BUILD_BASE}/boringssl/build/internal/android/${ARCH}/libssl.a
	EF=${BUILD_BASE}/boringssl/build/internal/android/${ARCH}/libcrypto.a
	FF=`find ${BUILD_BASE}/as_common/build/internal/android/obj/${ARCH}/ -name \*.o`

	GF=`find ${INTERNAL_DIR}/obj/${ARCH}/${MODNOM}/asma_embeddable/ -name \*.o`

	rm -f ${INTERNAL_DIR}/obj/${ARCH}/${MODNOM}/merged.o ${INTERNAL_DIR}/obj/${ARCH}/${MODNOM}/merged2.o
	LD=${NDK_PATH}/toolchains/${BASE}/prebuilt/${NDKHOST}/bin/${PREF}-ld
	${LD} -r ${AF} ${BF} ${CF} ${DF} ${EF} ${FF} ${GF} -o ${INTERNAL_DIR}/obj/${ARCH}/${MODNOM}/merged.o
	if [[ $? -ne 0 ]]; then
		echo ERROR building, aborting
		exit 1
	fi

	OC=${NDK_PATH}/toolchains/${BASE}/prebuilt/${NDKHOST}/bin/${PREF}-objcopy
	#${OC} -x \
	#	-G AS_JNI_OnLoad -G AS_Initialize -G AS_Register_Identity \
	#	-G AS_Send_Message -G AS_Heartbeat -G AS_Login_Status \
	#	-G AS_Network_Reachability -G AS_Version \
	#	${INTERNAL_DIR}/obj/${ARCH}/${MODNOM}/merged.o \
	#	${INTERNAL_DIR}/obj/${ARCH}/${MODNOM}/merged2.o
	${OC} -X -g --redefine-syms=syms.txt \
		-w -R .ARM.extab.* -R .ARM.exidx.* \
		${INTERNAL_DIR}/obj/${ARCH}/${MODNOM}/merged.o \
		${INTERNAL_DIR}/obj/${ARCH}/${MODNOM}/merged2.o

	rm -f ${INTERNAL_DIR}/obj/${ARCH}/${MODNOM}/libasma.a
	AR=${NDK_PATH}/toolchains/${BASE}/prebuilt/${NDKHOST}/bin/${PREF}-ar
	${AR} rcs ${INTERNAL_DIR}/obj/${ARCH}/${MODNOM}/libasma.a ${INTERNAL_DIR}/obj/${ARCH}/${MODNOM}/merged2.o
	if [[ $? -ne 0 ]]; then
		echo ERROR building, aborting
		exit 1
	fi

	S=${NDK_PATH}/toolchains/${BASE}/prebuilt/${NDKHOST}/bin/${PREF}-strip
	#${S} -w -R .ARM.extab.* -R .ARM.exidx.* \
	#${S} \
	#	-K AS_JNI_OnLoad -K AS_Initialize  \
	#	-K AS_Register_Identity -K AS_Send_Message \
	#	-K AS_Heartbeat -K AS_Login_Status \
	#	-K AS_Network_Reachability -K AS_Version \
 	#	${INTERNAL_DIR}/obj/${ARCH}/${MODNOM}/libasma.a
	${S} -g ${INTERNAL_DIR}/obj/${ARCH}/${MODNOM}/libasma.a
	if [[ $? -ne 0 ]]; then
		echo ERROR building, aborting
		exit 1
	fi

	${AR} s ${INTERNAL_DIR}/obj/${ARCH}/${MODNOM}/libasma.a
	if [[ $? -ne 0 ]]; then
		echo ERROR building, aborting
		exit 1
	fi

	mkdir -p ${RELEASE_DIR}/embeddable${EX}/lib/${ARCH}/

	cp ${INTERNAL_DIR}/obj/${ARCH}/${MODNOM}/libasma.a ${RELEASE_DIR}/embeddable${EX}/lib/${ARCH}/
	if [[ $? -ne 0 ]]; then
		echo ERROR building, aborting
		exit 1
	fi
}

build()
{
	ARCH=$1
	TOOLCHAIN=$2
	ASBUILD=$3

	export ARCH
	export ASBUILD

	echo ---- $ARCH -------------

	if [ "$ASBUILD" == "unity" ]; then
		APP_CFLAGS="${APP_CFLAGS} -DGAMEPROTECT"
	fi
	if [ "$ASBUILD" == "unitylite" ]; then
		APP_CFLAGS="${APP_CFLAGS} -DGAMEPROTECTLITE"
	fi

	${NDK_PATH}ndk-build APP_ABI=${ARCH} ARCH=${ARCH} NDK_TOOLCHAIN=${TOOLCHAIN} APP_CFLAGS="${APP_CFLAGS}"
	if [[ $? -ne 0 ]]; then
		echo ERROR building, aborting
		exit 1
	fi

	if [ "$ASBUILD" == "unity" ]; then
		mkdir -p ${RELEASE_DIR}/unity/lib/$ARCH/
		cp libs/${ARCH}/${LIBNOM}.so ${RELEASE_DIR}/unity/lib/$ARCH/
		${ASLIB_TOOL} ${ASLIB_SK} ${RELEASE_DIR}/unity/lib/${ARCH}/${LIBNOM}.so
		if [[ $? -ne 0 ]]; then
			echo ERROR building, aborting
			exit 1
		fi
	fi
	if [ "$ASBUILD" == "unitylite" ]; then
		mkdir -p ${RELEASE_DIR}/unitylite/lib/$ARCH/
		cp libs/${ARCH}/${LIBNOM}.so ${RELEASE_DIR}/unitylite/lib/$ARCH/
		${ASLIB_TOOL} ${ASLIB_SK} ${RELEASE_DIR}/unitylite/lib/${ARCH}/${LIBNOM}.so
		if [[ $? -ne 0 ]]; then
			echo ERROR building, aborting
			exit 1
		fi
	fi
	if [ "$ASBUILD" == "standalone" ]; then
		mkdir -p ${RELEASE_DIR}/standalone/lib/$ARCH/
		cp libs/${ARCH}/${LIBNOM}.so ${RELEASE_DIR}/standalone/lib/$ARCH/
		${ASLIB_TOOL} ${ASLIB_SK} ${RELEASE_DIR}/standalone/lib/${ARCH}/${LIBNOM}.so
		if [[ $? -ne 0 ]]; then
			echo ERROR building, aborting
			exit 1
		fi
	fi
	if [ "$ASBUILD" == "embedded" ]; then
		mkdir -p ${RELEASE_DIR}/embeddable/lib/$ARCH/
		mkdir -p ${INTERNAL_DIR}/embeddable/lib/$ARCH/
		cp obj/local/${ARCH}/${LIBNOM}_embeddable.a ${INTERNAL_DIR}/embeddable/lib/${ARCH}/
		mkdir -p ${INTERNAL_DIR}/obj/${ARCH}/${MODNOM}/
		cp -R obj/local/${ARCH}/objs/* ${INTERNAL_DIR}/obj/${ARCH}/${MODNOM}/
	fi
	if [ "$ASBUILD" == "emeasurable" ]; then
		mkdir -p ${RELEASE_DIR}/embeddable_measurable/lib/$ARCH/
		mkdir -p ${INTERNAL_DIR}/embeddable_measurable/lib/$ARCH/
		cp obj/local/${ARCH}/${LIBNOM}_embeddable.a ${INTERNAL_DIR}/embeddable_measurable/lib/${ARCH}/
		mkdir -p ${INTERNAL_DIR}/obj/${ARCH}/${MODNOM}/
		cp -R obj/local/${ARCH}/objs/* ${INTERNAL_DIR}/obj/${ARCH}/${MODNOM}/
	fi
}

rm -rf obj/
rm -rf libs/



#
# Build & process embedded versions
#

echo ======================================================
echo BUILDING: Embedded
echo ======================================================

${NDK_PATH}ndk-build clean

build "armeabi" "arm-linux-androideabi-clang" embedded
build "armeabi-v7a" "arm-linux-androideabi-clang" embedded
build "arm64-v8a" "aarch64-linux-android-clang" embedded
build "x86" "x86-clang" embedded
build "x86_64" "x86_64-clang" embedded

embprocess "armeabi" "arm-linux-androideabi-4.9" "arm-linux-androideabi" ""
embprocess "armeabi-v7a" "arm-linux-androideabi-4.9" "arm-linux-androideabi" ""
embprocess "arm64-v8a" "aarch64-linux-android-4.9" "aarch64-linux-android" ""
embprocess "x86" "x86-4.9" "i686-linux-android" ""
embprocess "x86_64" "x86_64-4.9" "x86_64-linux-android" ""

mkdir -p ${RELEASE_DIR}/embeddable/include/
cp ${HEADERS} ${RELEASE_DIR}/embeddable/include/

${NDK_PATH}ndk-build APP_BUILD_SCRIPT=jni/LinkTest.mk
if [[ $? -ne 0 ]]; then
	exit 1
fi




#
# Build & process embedded_measurable versions
#

echo ======================================================
echo BUILDING: Embedded_Measurable
echo ======================================================

${NDK_PATH}ndk-build clean

build "armeabi" "arm-linux-androideabi-clang" emeasurable
build "armeabi-v7a" "arm-linux-androideabi-clang" emeasurable
build "arm64-v8a" "aarch64-linux-android-clang" emeasurable
build "x86" "x86-clang" emeasurable
build "x86_64" "x86_64-clang" emeasurable

embprocess "armeabi" "arm-linux-androideabi-4.9" "arm-linux-androideabi" "_measurable"
embprocess "armeabi-v7a" "arm-linux-androideabi-4.9" "arm-linux-androideabi" "_measurable"
embprocess "arm64-v8a" "aarch64-linux-android-4.9" "aarch64-linux-android" "_measurable"
embprocess "x86" "x86-4.9" "i686-linux-android" "_measurable"
embprocess "x86_64" "x86_64-4.9" "x86_64-linux-android" "_measurable"

mkdir -p ${RELEASE_DIR}/embeddable_measurable/include/
cp ${HEADERS} ${RELEASE_DIR}/embeddable_measurable/include/




#
# Build & process standalone versions
#

echo ======================================================
echo BUILDING: Standalone
echo ======================================================

${NDK_PATH}ndk-build clean

build "armeabi" "arm-linux-androideabi-clang" standalone
build "armeabi-v7a" "arm-linux-androideabi-clang" standalone
build "arm64-v8a" "aarch64-linux-android-clang" standalone
build "x86" "x86-clang" standalone
build "x86_64" "x86_64-clang" standalone

# report sizes, which helps us see how much got included
echo ""
echo "Standalone Size:"
ls -al ../../build/release/android/standalone/lib/armeabi/${LIBNOM}.so
ls -al ../../build/release/android/standalone/lib/armeabi-v7a/${LIBNOM}.so
ls -al ../../build/release/android/standalone/lib/arm64-v8a/${LIBNOM}.so
ls -al ../../build/release/android/standalone/lib/x86/${LIBNOM}.so
ls -al ../../build/release/android/standalone/lib/x86_64/${LIBNOM}.so


#
# Build & process Unity/GameProtect versions
#

echo ======================================================
echo BUILDING: Unity/GameProtect
echo ======================================================

${NDK_PATH}ndk-build clean

build "armeabi-v7a" "arm-linux-androideabi-clang" unity
build "x86" "x86-clang" unity

#${NDK_PATH}ndk-build clean

#build "armeabi-v7a" "arm-linux-androideabi-clang" unitylite
#build "x86" "x86-clang" unitylite

# report sizes, which helps us see how much got included
echo ""
echo "Unity Size (Full):"
ls -al ../../build/release/android/unity/lib/armeabi-v7a/${LIBNOM}.so
ls -al ../../build/release/android/unity/lib/x86/${LIBNOM}.so

#echo ""
#echo "Unity Size (Lite):"
#ls -al ../../build/release/android/unitylite/lib/armeabi-v7a/${LIBNOM}.so
#ls -al ../../build/release/android/unitylite/lib/x86/${LIBNOM}.so

echo ======================================================
echo ASMA BUILD: Finish
echo ======================================================
