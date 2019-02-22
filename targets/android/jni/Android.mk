
LOCAL_PATH := $(call my-dir)
TARGET := android
ARCH := $(TARGET_ARCH_ABI)

TFS_LIB_D = $(BUILD_BASE)/tfs_lib/build/internal/$(TARGET)/
TFS_LIBC_D := $(BUILD_BASE)/tfs_libc/build/internal/$(TARGET)/
TFS_MBED_D := $(BUILD_BASE)/tfs_mbedtls/build/internal/$(TARGET)/
TFS_BSSL_D := $(BUILD_BASE)/boringssl/build/internal/$(TARGET)/

AS_COMMON_D = $(BUILD_BASE)/as_common/build/internal/$(TARGET)/

#EXTOBJ := $(shell find $(TFS_LIB_D)/obj/$(ARCH)/ -type f -name \*.o)
#EXTOBJ += $(shell find $(AS_COMMON_D)/obj/$(ARCH)/ -type f -name \*.o)
#EXTOBJ += $(shell find $(TFS_MBED_D)/obj/$(ARCH)/ -type f -name \*.o)

TFSLIBC ?= libc

ifndef TFSCAL
$(error TFSCAL is not set)
endif

#########################################
# Prebuilts

include $(CLEAR_VARS)
LOCAL_MODULE := tfslibc-prebuilt
LOCAL_SRC_FILES := $(TFS_LIBC_D)/lib/$(ARCH)/libtfs_libc.a
include $(PREBUILT_STATIC_LIBRARY)

include $(CLEAR_VARS)
LOCAL_MODULE := tfs-prebuilt
LOCAL_SRC_FILES := $(TFS_LIB_D)/lib/$(ARCH)/libtfs.a
include $(PREBUILT_STATIC_LIBRARY)

SSLSTACK ?= boringssl

ifeq ($(SSLSTACK),mbedtls)
  include $(CLEAR_VARS)
  LOCAL_MODULE := ssl-prebuilt
  LOCAL_SRC_FILES := $(TFS_MBED_D)/lib/$(ARCH)/libmbedtls.a
  include $(PREBUILT_STATIC_LIBRARY)
endif

ifeq ($(SSLSTACK),boringssl)
  include $(CLEAR_VARS)
  LOCAL_MODULE := ssl-prebuilt
  LOCAL_SRC_FILES := $(TFS_BSSL_D)/$(ARCH)/libssl.a
  include $(PREBUILT_STATIC_LIBRARY)

  include $(CLEAR_VARS)
  LOCAL_MODULE := ssl-prebuilt2
  LOCAL_SRC_FILES := $(TFS_BSSL_D)/$(ARCH)/libcrypto.a
  include $(PREBUILT_STATIC_LIBRARY)
endif

include $(CLEAR_VARS)
LOCAL_MODULE := ascommon-prebuilt
LOCAL_SRC_FILES := $(AS_COMMON_D)/lib/$(ARCH)/libas_common.a
include $(PREBUILT_STATIC_LIBRARY)

#########################################
# Static library

include $(CLEAR_VARS)
LOCAL_MODULE := libasma_embeddable

INCS := \
	-I$(TFS_LIB_D)/include/ \
	-I$(AS_COMMON_D)/include/ \
        -I$(TFS_MBED_D)/include/ \
        -I$(TFS_LIBC_D)/include/ \
	-Ijni/src/ \
	-Ijni/src/observations/ \
	-Ijni/src_GENERATED/$(TARGET)/ \
        -Ijni/common/ \
	-Ijni/common/observations/ \
        -Ijni/common/nanopb/ \
	-Ijni/common/config_parser/ 


DEFS += -DPLATFORM_H=\"platform.$(TFSLIBC).h\" -DTARGET=$(TARGET) \
	-DSYSTEMID=2 -DDEFSIDENT=2 -DASVERSION=$(VERSION) \
	-DTFQF_INTEGRITY -D_GNU_SOURCE -DTFSCAL=$(TFSCAL)

ifeq ($(ASBUILD),standalone)
	DEFS += -DBUILD_STANDALONE
endif
ifeq ($(ASBUILD),unity)
	DEFS += -DBUILD_STANDALONE -DUNITY
endif
ifeq ($(ASBUILD),emeasurable)
	DEFS += -DBUILD_MEASURABLE
endif

LOCAL_CFLAGS += -O3 $(INCS) $(DEFS) -fPIE -fPIC -fno-exceptions \
        -ffast-math -fno-unwind-tables -fvisibility=hidden \
	-fomit-frame-pointer -finline-limit=64 \
	-fno-asynchronous-unwind-tables

LOCAL_CPPFLAGS += $(LOCAL_CFLAGS)

LOCAL_SRC_FILES := \
	src/jni_layer.cpp \
	src/embedded_layer.cpp \
	src/bootstrap_pre.cpp \
	src/watchers.c \
	src/proxy.cpp \
	src/stealth_callbacks.cpp \
	src/observations/observations_pkgs.c \
	src/observations/observations_java.cpp \
	src/observations/observations_common.c \
	src/utils/properties.c \
	src/utils/mutex_timedlock.c \
	common/bootstrap.c \
	common/message.c \
	common/customer.c \
	common/heartbeat.c \
	common/misc.c \
	common/guarded_data.c \
	common/error_reporting.c \
	common/analytics.c \
	common/ssl_violation.c 

DISABLED := \
	common/config_parser/config_parser.c \
	common/observations/observations_files.c 


include $(BUILD_STATIC_LIBRARY)


#####################################################
# Conditional standalone

DO_STANDALONE := 0
ifeq ($(ASBUILD),standalone)
 DO_STANDALONE := 1
else ifeq ($(ASBUILD),unity)
 DO_STANDALONE := 1
endif

ifeq ($(DO_STANDALONE),1)

#ifeq ($(ASBUILD),unity)
#	DEFS += -DBUILD_STANDALONE -DUNITY
# endif

 include $(CLEAR_VARS)
 LOCAL_MODULE := libasma

 LOCAL_SRC_FILES := \
	src/jni_standalone.cpp

 LOCAL_CFLAGS += -O3 $(INCS) $(DEFS) -fPIE -fPIC -fno-exceptions \
        -ffast-math -fno-unwind-tables -fvisibility=hidden \
	-fomit-frame-pointer -finline-limit=64 \
	-fno-asynchronous-unwind-tables
 LOCAL_CPPFLAGS += $(LOCAL_CFLAGS)

 LOCAL_LDFLAGS += -Wl,--gc-sections 
 LOCAL_STATIC_LIBRARIES :=  libasma_embeddable tfs-prebuilt \
	ascommon-prebuilt ssl-prebuilt ssl-prebuilt2 tfslibc-prebuilt
 LOCAL_LDLIBS := -llog -landroid

 include $(BUILD_SHARED_LIBRARY)

endif


