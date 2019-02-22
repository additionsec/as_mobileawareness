#!/bin/sh

SIGN_TOOL=../../tfs_lib/targets/darwin/build/tools/tool_dual_sign
KF1=ecc_offline_1.key.raw
KF2=rsa_offline_1.key.der

$SIGN_TOOL ../keys/$KF1 ../keys/$KF2 ../build/internal/ios/RELEASE.defs
$SIGN_TOOL ../keys/$KF1 ../keys/$KF2 ../build/internal/android/RELEASE.defs

