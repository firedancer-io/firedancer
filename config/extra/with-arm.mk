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
include config/extra/with-secp256k1.mk
include config/extra/with-zstd.mk
include config/extra/with-bzip2.mk
include config/extra/with-lz4.mk
include config/extra/with-openssl.mk
include config/extra/with-rocksdb.mk

endif

FD_ARCH_SUPPORTS_SANDBOX:=1

CPPFLAGS+=-DFD_HAS_ARM=1
FD_HAS_ARM:=1
