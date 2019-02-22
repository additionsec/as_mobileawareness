#!/bin/sh

RELEASE_DIR=../../build/release/unity/
ANDROID_DIR=../../build/release/android/
IOS_DIR=../../build/release/ios/

# These names are particular to Unity
rm -rf ${RELEASE_DIR}/
mkdir -p ${RELEASE_DIR}/Plugins/Resources/
mkdir -p ${RELEASE_DIR}/Plugins/Android/Resources/
mkdir -p ${RELEASE_DIR}/Plugins/Android/libs/
mkdir -p ${RELEASE_DIR}/Plugins/iOS/Resources/

cp MobileAwareness.cs ${RELEASE_DIR}/Plugins/

cp -r ${ANDROID_DIR}/unity/lib/* ${RELEASE_DIR}/Plugins/Android/libs/
cp ${ANDROID_DIR}/assets/as.def ${RELEASE_DIR}/Plugins/Android/Resources/asdef_a.bytes
cp ${ANDROID_DIR}/embeddable/java/asma-embedded.jar ${RELEASE_DIR}/Plugins/Android/

cp as_mobileawareness_bridge.m ${RELEASE_DIR}/Plugins/iOS/
cp ${IOS_DIR}/sdk_standalone/AdditionSecurity/as.def ${RELEASE_DIR}/Plugins/iOS/Resources/asdef_i.bytes
cp ${IOS_DIR}/sdk_standalone/AdditionSecurity/libasma.a ${RELEASE_DIR}/Plugins/iOS/

echo ======================================================
echo UNITY - PACKAGED
echo ======================================================
