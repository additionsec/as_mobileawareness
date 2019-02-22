#!/bin/sh

RELEASE_DIR=../../build/release/kony/
ANDROID_DIR=../../build/release/android/
IOS_DIR=../../build/release/ios/

JAVAOUT=android/MobileAwarenessKony/asma/build/outputs/aar/

rm -rf ${RELEASE_DIR}/*
mkdir -p ${RELEASE_DIR}/

CWD=`pwd`
cd android/MobileAwarenessKony/
./gradlew assembleStandalone
[ $? -eq 0 ] || exit $?
cd ${CWD}

if [ ! -e "${JAVAOUT}/asma-standalone.aar" ]; then
	echo "ERROR: Build asma-standalone.aar"
	exit 1
fi


mkdir -p ${RELEASE_DIR}/staging/
cp -R plugin/* ${RELEASE_DIR}/staging/

cp ${JAVAOUT}/asma-standalone.aar /tmp/asma.aar
unzip /tmp/asma.aar -d /tmp/ classes.jar
cp /tmp/classes.jar ${RELEASE_DIR}/staging/resources/customlibs/lib/android/asma-standalone-kony.jar
cp /tmp/classes.jar ${RELEASE_DIR}/staging/resources/customlibs/lib/tabrcandroid/asma-standalone-kony.jar
rm -f /tmp/classes.jar /tmp/asma.aar

cp -R ${ANDROID_DIR}/standalone/jniLibs/armeabi ${RELEASE_DIR}/staging/resources/customlibs/lib/android/
cp -R ${ANDROID_DIR}/standalone/jniLibs/armeabi ${RELEASE_DIR}/staging/resources/customlibs/lib/tabrcandroid/
cp -R ${ANDROID_DIR}/standalone/jniLibs/x86 ${RELEASE_DIR}/staging/resources/customlibs/lib/android/
cp -R ${ANDROID_DIR}/standalone/jniLibs/x86 ${RELEASE_DIR}/staging/resources/customlibs/lib/tabrcandroid/

cp ${ANDROID_DIR}/assets/as.def ${RELEASE_DIR}/staging/resources/mobile/native/android/assets/
# NOTE: this "andriod" misspelling is intentional, and required by Kony:
cp ${ANDROID_DIR}/assets/as.def ${RELEASE_DIR}/staging/resources/tablet/native/andriodtab/assets/

mkdir -p ${RELEASE_DIR}/staging2/
cp ${IOS_DIR}/sdk_systemcrypto/AdditionSecurity/as.def ${RELEASE_DIR}/staging2/
cp ${IOS_DIR}/sdk_systemcrypto/AdditionSecurity/as_mobileawareness.h ${RELEASE_DIR}/staging2/
cp ${IOS_DIR}/sdk_systemcrypto/AdditionSecurity/libasma.a ${RELEASE_DIR}/staging2/
cp ios/* ${RELEASE_DIR}/staging2/

CWD=`pwd`
cd ${RELEASE_DIR}/staging2/
zip ../staging/resources/customlibs/lib/iphone/mobileawareness.zip *
cd ${CWD}
cp ${RELEASE_DIR}/staging/resources/customlibs/lib/iphone/mobileawareness.zip \
	${RELEASE_DIR}/staging/resources/customlibs/lib/ipad/mobileawareness.zip 

cd ${RELEASE_DIR}/staging/
zip -r -D ../MobileAwareness_Kony.zip * -x \*.DS_Store

echo ======================================================
echo KONY - PACKAGED
echo ======================================================
