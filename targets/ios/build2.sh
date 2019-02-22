#!/bin/bash

# From https://raw.githubusercontent.com/st3fan/ios-openssl/master/build.sh

PRODUCT=asma
LIBNOM=libasma

#set -x

DEVELOPER="/Applications/Xcode.app/Contents/Developer"

#SDK_VERSION="9.3"
#MIN_VERSION="6.0"

IPHONEOS_PLATFORM="${DEVELOPER}/Platforms/iPhoneOS.platform"
IPHONEOS_SDK="${IPHONEOS_PLATFORM}/Developer/SDKs/iPhoneOS${SDK_VERSION}.sdk"
IPHONEOS_GCC="/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/clang"
IPHONEOS_AR="/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/ar"

IPHONESIMULATOR_PLATFORM="${DEVELOPER}/Platforms/iPhoneSimulator.platform"
IPHONESIMULATOR_SDK="${IPHONESIMULATOR_PLATFORM}/Developer/SDKs/iPhoneSimulator${SDK_VERSION}.sdk"
IPHONESIMULATOR_GCC="/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/clang"
IPHONESIMULATOR_AR="/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/ar"


if [ ! -d "$IPHONEOS_PLATFORM" ]; then
  echo "Cannot find $IPHONEOS_PLATFORM"
  exit 1
fi

if [ ! -d "$IPHONEOS_SDK" ]; then
  echo "Cannot find $IPHONEOS_SDK"
  exit 1
fi

if [ ! -x "$IPHONEOS_GCC" ]; then
  echo "Cannot find $IPHONEOS_GCC"
  exit 1
fi

if [ ! -d "$IPHONESIMULATOR_PLATFORM" ]; then
  echo "Cannot find $IPHONESIMULATOR_PLATFORM"
  exit 1
fi

if [ ! -d "$IPHONESIMULATOR_SDK" ]; then
  echo "Cannot find $IPHONESIMULATOR_SDK"
  exit 1
fi

if [ ! -x "$IPHONESIMULATOR_GCC" ]; then
  echo "Cannot find $IPHONESIMULATOR_GCC"
  exit 1
fi

rm -rf build/

build()
{
   TARGET=$1
   ARCH=$2
   GCC=$3
   SDK=$4
   AR=$5

   CC="${GCC} -arch ${ARCH} -miphoneos-version-min=${MIN_VERSION}"
   CFLAGS="-isysroot ${SDK} -fembed-bitcode"
   LDFLAGS=""

   export ARCH
   export CC
   export AR
   export CFLAGS
   export LDFLAGS

   #make clean
   make 
   [ $? -eq 0 ] || exit $?
}

build "BSD-generic32" "armv7" "${IPHONEOS_GCC}" "${IPHONEOS_SDK}" "${IPHONEOS_AR}"
build "BSD-generic32" "armv7s" "${IPHONEOS_GCC}" "${IPHONEOS_SDK}" "${IPHONEOS_AR}"
build "BSD-generic64" "arm64" "${IPHONEOS_GCC}" "${IPHONEOS_SDK}" "${IPHONEOS_AR}"

# x86 always uses libc
TFSLIBC=libc
export TFSLIBC
build "BSD-generic32" "i386" "${IPHONESIMULATOR_GCC}" "${IPHONESIMULATOR_SDK}" "${IPHONESIMULATOR_AR}"
build "BSD-generic64" "x86_64" "${IPHONESIMULATOR_GCC}" "${IPHONESIMULATOR_SDK}" "${IPHONESIMULATOR_AR}"


lipo \
	"build/lib/${LIBNOM}_armv7.a" \
	"build/lib/${LIBNOM}_armv7s.a" \
	"build/lib/${LIBNOM}_arm64.a" \
	"build/lib/${LIBNOM}_i386.a" \
	"build/lib/${LIBNOM}_x86_64.a" \
	-create -output build/lib/${LIBNOM}.a



