
NM=${NDK_PATH}/toolchains/arm-linux-androideabi-4.9/prebuilt/darwin-x86_64/bin/arm-linux-androideabi-nm

${NM} ${BUILD_BASE}/tfs_libc/build/internal/android/lib/armeabi/libtfs_libc.a > syms.input
${NM} ${BUILD_BASE}/tfs_lib/build/internal/android/lib/armeabi/libtfs.a >> syms.input
${NM} ${BUILD_BASE}/as_common/build/internal/android/lib/armeabi/libas_common.a >> syms.input
${NM} ${BUILD_BASE}/as_mobileawareness/build/internal/android/embeddable/lib/armeabi/libasma_embeddable.a >> syms.input
