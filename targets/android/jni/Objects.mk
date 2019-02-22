
TARGET := android

AS_BASE := as/

TFS_LIB_D = $(AS_BASE)/tfs_lib/build/internal/$(TARGET)/
AS_COMMON_D = $(AS_BASE)/as_common/build/internal/$(TARGET)/
AS_LIBC_D := $(AS_BASE)/as_libc/build/internal/$(TARGET)/
#AS_MBED_D := $(AS_BASE)/as_mbedtls/build/internal/$(TARGET)/

EXTOBJ := $(shell find $(TFS_LIB_D)/obj/$(ARCH)/ -type f -name \*.o)
EXTOBJ := $(shell find $(AS_LIBC_D)/obj/$(ARCH)/ -type f -name \*.o)
EXTOBJ += $(shell find $(AS_COMMON_D)/obj/$(ARCH)/ -type f -name \*.o)
#EXTOBJ += $(shell find $(AS_MBED_D)/obj/$(ARCH)/ -type f -name \*.o)

libdependencies.a:
	$(LD) $(LDFLAGS) -r $(EXTOBJ) -o $(BUILD_DIR)/lib/$@.o
