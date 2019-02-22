#!/bin/sh

TOOLS_DIR=../../tfs_lib/tools/defsengine/
RELEASE_DIR=../build/release/
INTERNAL_DIR=../build/internal/

STYPE_HASH=1
STYPE_HASHMATCH=2
STYPE_STRING=3

SECT_FILES=1
SECT_APPS=2
SECT_SYMS=3
SECT_LIBS=4
SECT_SIGS=5
SECT_ENV=6
SECT_PROPS=7
SECT_HOOKS=8
SECT_PROXY=9
SECT_APPROVED=10

#################################################################################
# Android
IDENT=2
WD=${INTERNAL_DIR}/android/
FLAGS=defs/android_flags.txt
echo "Building android RELEASE.defs"

# clean out prior
mkdir -p $WD/
rm -rf $WD/.defs $WD/RELEASE.defs

# make sections
mkdir -p $WD/.defs

perl ${TOOLS_DIR}/section_pkgs.pl defs/android_pkgs.txt $FLAGS > ${WD}/.defs/section_pkgs.bin
[ $? -eq 0 ] || exit 1

perl ${TOOLS_DIR}/section_strings2.pl defs/android_files.txt $FLAGS > ${WD}/.defs/section_files.bin
[ $? -eq 0 ] || exit 1

perl ${TOOLS_DIR}/section_strings2.pl defs/android_libs.txt $FLAGS > ${WD}/.defs/section_libs.bin
[ $? -eq 0 ] || exit 1

perl ${TOOLS_DIR}/section_strings2.pl defs/proxy.txt $FLAGS > ${WD}/.defs/section_proxy.bin
[ $? -eq 0 ] || exit 1

perl ${TOOLS_DIR}/section_strings2.pl defs/android_env.txt $FLAGS > ${WD}/.defs/section_env.bin
[ $? -eq 0 ] || exit 1

perl ${TOOLS_DIR}/section_sigs.pl defs/android_bad_signers.txt $FLAGS > ${WD}/.defs/section_signers.bin
[ $? -eq 0 ] || exit 1

#perl ${TOOLS_DIR}/section_strings3.pl defs/android_props.txt $FLAGS > ${WD}/.defs/section_props.bin
perl ${TOOLS_DIR}/section_strings2.pl defs/android_props.txt $FLAGS > ${WD}/.defs/section_props.bin
[ $? -eq 0 ] || exit 1

perl ${TOOLS_DIR}/section_strings2.pl defs/android_symbols.txt $FLAGS > ${WD}/.defs/section_syms.bin
[ $? -eq 0 ] || exit 1

perl ${TOOLS_DIR}/section_strings2.pl defs/android_hooks.txt ${FLAGS} > ${WD}/.defs/section_hooks.bin
[ $? -eq 0 ] || exit 1


# combine sections into total
perl ${TOOLS_DIR}/sections_assemble.pl ${IDENT} \
	${SECT_FILES}:${STYPE_STRING}:${WD}/.defs/section_files.bin \
	${SECT_APPS}:${STYPE_HASH}:${WD}/.defs/section_pkgs.bin \
	${SECT_SIGS}:${STYPE_HASH}:${WD}/.defs/section_signers.bin \
	${SECT_LIBS}:${STYPE_STRING}:${WD}/.defs/section_libs.bin \
	${SECT_ENV}:${STYPE_STRING}:${WD}/.defs/section_env.bin \
	${SECT_PROPS}:${STYPE_STRING}:${WD}/.defs/section_props.bin \
	${SECT_HOOKS}:${STYPE_STRING}:${WD}/.defs/section_hooks.bin \
	${SECT_SYMS}:${STYPE_STRING}:${WD}/.defs/section_syms.bin \
	${SECT_PROXY}:${STYPE_STRING}:${WD}/.defs/section_proxy.bin \
	> ${WD}/RELEASE.defs
[ $? -eq 0 ] || exit 2
ls -al ${WD}/RELEASE.defs



#################################################################################
# IOS
IDENT=1
WD=${INTERNAL_DIR}/ios/
FLAGS=defs/ios_flags.txt
echo "Building ios RELEASE.defs"

# clean out prior
mkdir -p $WD/include/
rm -rf $WD/.defs $WD/RELEASE.defs

# make sections
mkdir -p $WD/.defs

perl ${TOOLS_DIR}/section_strings2.pl defs/ios_files.txt ${FLAGS} > ${WD}/.defs/section_files.bin
[ $? -eq 0 ] || exit 1

perl ${TOOLS_DIR}/section_strings2.pl defs/ios_symbols.txt ${FLAGS} > ${WD}/.defs/section_symbols.bin
[ $? -eq 0 ] || exit 1

perl ${TOOLS_DIR}/section_strings2.pl defs/proxy.txt ${FLAGS} > ${WD}/.defs/section_proxy.bin
[ $? -eq 0 ] || exit 1

perl ${TOOLS_DIR}/section_strings2.pl defs/ios_dylibs.txt ${FLAGS} > ${WD}/.defs/section_dylibs.bin
[ $? -eq 0 ] || exit 1

perl ${TOOLS_DIR}/section_strings2.pl defs/ios_hooks.txt ${FLAGS} > ${WD}/.defs/section_hooks.bin
[ $? -eq 0 ] || exit 1

perl ${TOOLS_DIR}/section_strings2.pl defs/ios_env.txt $FLAGS > ${WD}/.defs/section_env.bin
[ $? -eq 0 ] || exit 1

perl ${TOOLS_DIR}/section_pkgs.pl defs/ios_objc_approved_dylibs.txt $FLAGS > ${WD}/.defs/section_approved_dylibs.bin
[ $? -eq 0 ] || exit 1

# combine sections into total
perl ${TOOLS_DIR}/sections_assemble.pl ${IDENT} \
	${SECT_SYMS}:${STYPE_STRING}:${WD}/.defs/section_symbols.bin \
	${SECT_FILES}:${STYPE_STRING}:${WD}/.defs/section_files.bin \
	${SECT_LIBS}:${STYPE_STRING}:${WD}/.defs/section_dylibs.bin \
	${SECT_HOOKS}:${STYPE_STRING}:${WD}/.defs/section_hooks.bin \
	${SECT_ENV}:${STYPE_STRING}:${WD}/.defs/section_env.bin \
	${SECT_PROXY}:${STYPE_STRING}:${WD}/.defs/section_proxy.bin \
	${SECT_APPROVED}:${STYPE_HASH}:${WD}/.defs/section_approved_dylibs.bin \
	> ${WD}/RELEASE.defs
[ $? -eq 0 ] || exit 2
ls -al ${WD}/RELEASE.defs


#################################################################################

echo "Done"
exit 0
