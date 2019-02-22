
LIBNOM := libasma
TARGET := ios
BUILD_DIR = build/
ARCH ?= host

ifndef TFSCAL
$(error TFSCAL is not set)
endif

SIMULATOR := 0
ifeq ($(ARCH),$(filter $(ARCH),i386 x86_64))
  SIMULATOR := 1
endif

##############################################

TFS_LIB_D := $(BUILD_BASE)/tfs_lib/build/internal/$(TARGET)/
TFS_LIBC_D := $(BUILD_BASE)/tfs_libc/build/internal/$(TARGET)/
TFS_MBED_D := $(BUILD_BASE)/tfs_mbedtls/build/internal/$(TARGET)/

AS_COMMON_D := $(BUILD_BASE)/as_common/build/internal/$(TARGET)/

TFSLIBC ?= libc

INCS := \
	-I$(TFS_LIB_D)/include/ \
	-I$(AS_COMMON_D)/include/ \
	-I$(TFS_MBED_D)/include/ \
	-I$(TFS_LIBC_D)/include/ \
	-Isrc/ \
	-Isrc/observations/ \
	-Isrc_GENERATED/$(TARGET)/ \
	-Icommon/ \
	-Icommon/observations/ \
	-Icommon/config_parser

SRC := \
	src/sdk_main.c \
	src/stealth_callbacks.c \
	src/watchers.c \
	src/proxy.c \
	src/observations/observations_common.c \
	common/guarded_data.c \
	common/bootstrap.c \
	common/message.c \
	common/customer.c \
	common/heartbeat.c \
	common/mitm.c \
	common/misc.c \
	common/error_reporting.c \
	common/analytics.c \
	common/ssl_violation.c 

# files for non-simulator
ifeq ($(SIMULATOR),0)
  SRC += \
	src/observations/observations_dylibs.c 
endif

OBJ_DIR = $(BUILD_DIR)/obj_$(ARCH)/
OBJ = $(SRC:%.c=$(OBJ_DIR)/%.o)

HEADERS := src/as_mobileawareness.h

EXTOBJ := $(shell find $(TFS_LIB_D)/obj/$(ARCH)/ -type f -name \*.o)
EXTOBJ += $(shell find $(TFS_LIBC_D)/obj/$(ARCH)/ -type f -name \*.o)
EXTOBJ += $(shell find $(AS_COMMON_D)/obj/$(ARCH)/ -type f -name \*.o)

ifeq ($(SSLSTACK),mbedtls)
  EXTOBJ += $(shell find $(TFS_MBED_D)/obj/$(ARCH)/ -type f -name \*.o)
endif

##############################################

DEFS := -DPLATFORM_H=\"platform.$(TFSLIBC).h\" -DTARGET=$(TARGET) \
	-DSYSTEMID=1 -DDEFSIDENT=1 -DASVERSION=$(VERSION) \
	-DTFQF_INTEGRITY 

CFLAGS += -O3 $(INCS) $(DEFS) -fPIC -fno-exceptions \
	-ffast-math -fno-unwind-tables -fvisibility=hidden \
	-fomit-frame-pointer -fno-asynchronous-unwind-tables \
	$(APP_CFLAGS)


ifeq ($(TFSCAL),apple)
  DEFS += -DSIGN_WITH_RSA
endif

##############################################

.PHONY: default build clean link title

default: title build link

title:
	@echo ------ arch $(ARCH) ---------

build: $(LIBNOM)_$(ARCH).a
	@mkdir -p $(BUILD_DIR)/include/
	@cp $(HEADERS) $(BUILD_DIR)/include/
	@echo '' >> $(BUILD_DIR)/build.environment
	@echo $(LIBNOM)_$(ARCH) >> $(BUILD_DIR)/build.environment
	@$(CC) $(CFLAGS) --version >> $(BUILD_DIR)/build.environment
	@echo $(CFLAGS) >> $(BUILD_DIR)/build.environment

$(OBJ): $(OBJ_DIR)/%.o: %.c
	@mkdir -p $(@D)
	@echo - CC $<
	@$(CC) $(CFLAGS) -c -o $@ $<

$(LIBNOM)_$(ARCH).a: $(OBJ)
	@mkdir -p $(BUILD_DIR)/lib/
	@$(LD) $(LDFLAGS) -r -bitcode_bundle $(EXTOBJ) $(OBJ) -o $(BUILD_DIR)/lib/$@.o
	@$(AR) rcs $(BUILD_DIR)/lib/$@ $(BUILD_DIR)/lib/$@.o
	@strip -x $(BUILD_DIR)/lib/$@

link: $(LIBNOM)_$(ARCH).a
	@$(CC) $(CFLAGS) -framework Foundation -framework Security -framework CFNetwork -o $(BUILD_DIR)/test_link src/test_link.c $(BUILD_DIR)/lib/$(LIBNOM)_$(ARCH).a

clean:
	rm -rf $(BUILD_DIR)/
