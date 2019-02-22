#!/bin/sh

TOOLS_DIR=../../tfs_lib/tools/defsengine/
GEN_DIR=../src_GENERATED/

#################################################################################
# Android
WD=${GEN_DIR}/android/
FLAGS=defs/android_flags.txt

mkdir -p $WD/
rm -rf $WD/as_defs_flags.h
cat ${FLAGS} | perl ${TOOLS_DIR}/flags_to_defines.pl ASDEFS_FLAGS >> ${WD}/as_defs_flags.h
[ $? -eq 0 ] || exit 1

#################################################################################
# IOS
WD=${GEN_DIR}/ios/
FLAGS=defs/ios_flags.txt

mkdir -p $WD/
rm -rf $WD/as_defs_flags.h
cat ${FLAGS} | perl ${TOOLS_DIR}/flags_to_defines.pl ASDEFS_FLAGS >> ${WD}/as_defs_flags.h
[ $? -eq 0 ] || exit 2

#################################################################################

echo "Done"
exit 0
