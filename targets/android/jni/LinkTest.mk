
LOCAL_PATH := $(call my-dir)
TARGET := android
ARCH := $(TARGET_ARCH_ABI)

#########################################
# Prebuilts

include $(CLEAR_VARS)
LOCAL_MODULE := libasma_prebuilt
LOCAL_SRC_FILES := $(BUILD_BASE)/as_mobileawareness/build/release/android/embeddable/lib/$(ARCH)/libasma.a
include $(PREBUILT_STATIC_LIBRARY)

#####################################################
# Conditional standalone

include $(CLEAR_VARS)
LOCAL_MODULE := libasma_linktest

LOCAL_SRC_FILES := EMBEDDED_LINK_TEST.cpp

INCS := -I$(BUILD_BASE)/as_mobileawareness/build/release/android/embeddable/include/
LOCAL_CFLAGS += -O3 $(INCS) $(DEFS) -fPIE -fPIC -fno-exceptions \
        -ffast-math -fno-unwind-tables -fvisibility=hidden \
	-fomit-frame-pointer -finline-limit=64 \
	-fno-asynchronous-unwind-tables
LOCAL_CPPFLAGS += $(LOCAL_CFLAGS)

LOCAL_LDFLAGS += -Wl,--gc-sections 
LOCAL_STATIC_LIBRARIES :=  libasma_prebuilt
LOCAL_LDLIBS := -llog -landroid

include $(BUILD_SHARED_LIBRARY)


