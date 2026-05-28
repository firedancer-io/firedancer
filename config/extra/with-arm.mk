# Experimental Arm support.
# Requires at least Armv8.4-a (LSE2 and RCPC3)

ifneq ($(filter-out aarch64 arm64,$(shell uname -m)),)
# uname -m is not empty and is neither aarch64 nor arm64
CROSS=1
endif

ifeq ($(CROSS),1)
$(warning Cross compiling for Arm)

# Delete default flags
CPPFLAGS:=
LDFLAGS:=-lm

TARGET?=aarch64-linux-gnu
CROSS_LD?=$(TARGET)-$(LD)
LD:=$(CROSS_LD)

ifdef FD_USING_GCC
CROSS_CC?=$(TARGET)-$(CC)
CROSS_CXX?=$(TARGET)-$(CXX)
CC:=$(CROSS_CC)
CXX:=$(CROSS_CXX)
endif

ifdef FD_USING_CLANG
CPPFLAGS+=-target $(TARGET)
endif

else # CROSS=0

include config/extra/with-ucontext.mk
include config/extra/with-s2nbignum.mk
include config/extra/with-blst.mk
include config/extra/with-zstd.mk
include config/extra/with-lz4.mk
include config/extra/with-openssl.mk
include config/extra/with-rocksdb.mk

endif

FD_ARCH_SUPPORTS_SANDBOX:=1

CPPFLAGS+=-DFD_HAS_ARM=1
FD_HAS_ARM:=1

CPPFLAGS+=-DFD_HAS_NEON=1
FD_HAS_NEON:=1

define _arm_map_define
  ifeq ($(shell echo | $(CC) $(CPPFLAGS) -E -dM - | grep -c $(2)),1)
    CPPFLAGS+=-D$(1)=1
    $(1):=1
  endif
endef

arm-map-define = $(eval $(call _arm_map_define,$(1),$(2)))

$(call arm-map-define,FD_HAS_ARM_AES,__ARM_FEATURE_AES)
$(call arm-map-define,FD_HAS_ARM_CRYPTO,__ARM_FEATURE_CRYPTO)
$(call arm-map-define,FD_HAS_ARM_SHA256,__ARM_FEATURE_SHA2)
$(call arm-map-define,FD_HAS_ARM_SHA512,__ARM_FEATURE_SHA512)

ifdef FD_HAS_ARM_AES
ifndef FD_HAS_ARM_CRYPTO
CPPFLAGS+=-DFD_HAS_ARM_CRYPTO=1
FD_HAS_ARM_CRYPTO:=1
endif
endif
