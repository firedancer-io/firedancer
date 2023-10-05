define _map-define
  ifeq ($(shell echo | $(CC) -march=native -E -dM - | grep -c $(2)),1)
    CPPFLAGS+=-D$(1)=1
    $(1):=1
  endif
endef

map-define = $(eval $(call _map-define,$(1),$(2)))

define _check-define
    $(eval $(1) := $(shell echo | $(CC) -march=native -E -dM - | grep -q $(2) && echo 1 || echo 0))
endef

check-define = $(eval $(call _check-define,$(1),$(2)))

CC?=gcc

$(call check-define, FD_USING_CLANG, __clang__)

$(call check-define, FD_IS_GNU, __GNUC__)
ifeq ($(FD_IS_GNU),1)
    ifneq ($(FD_USING_CLANG),1)
        FD_USING_GCC := 1
    endif
endif

ifeq ($(FD_USING_GCC),1)
include config/base.mk
	CC:=gcc
	CXX:=g++
	LD:=g++
else ifeq ($(FD_USING_CLANG),1)
include config/base.mk
	CC=clang
	CXX=clang++
	LD=clang++
endif

BUILDDIR?=native/$(CC)
CPPFLAGS+=-march=native -mtune=native

include config/with-brutality.mk
include config/with-optimization.mk
include config/with-debug.mk

$(call map-define,FD_HAS_SHANI, __SHA__)
$(call map-define,FD_HAS_INT128, __SIZEOF_INT128__)
FD_HAS_DOUBLE:=1
CPPFLAGS+=-DFD_HAS_DOUBLE=1
FD_HAS_ALLOCA:=1
CPPFLAGS+=-DFD_HAS_ALLOCA=1
FD_HAS_THREADS:=1
CPPFLAGS+=-DFD_HAS_THREADS=1
FD_HAS_OPENSSL:=1
CPPFLAGS+=-DFD_HAS_OPENSSL=1
FD_HAS_X86:=1
CPPFLAGS+=-DFD_HAS_X86=1
$(call map-define,FD_HAS_SSE, __SSE4_2__)
$(call map-define,FD_HAS_AVX, __AVX2__)
$(call map-define,FD_HAS_GFNI, __GFNI__)

$(info Using FD_HAS_SSE=$(FD_HAS_SSE))
$(info Using FD_HAS_AVX=$(FD_HAS_AVX))
$(info Using FD_HAS_GFNI=$(FD_HAS_GFNI))
$(info Using FD_HAS_SHANI=$(FD_HAS_SHANI))

ifeq ($(FD_HAS_X86),1)
include config/with-threads.mk
include config/with-openssl.mk
include config/with-bz2.mk
include config/with-zstd.mk
include config/with-rocksdb.mk
include config/with-secp256k1.mk
include config/x86-64-flags.mk
	ifeq ($(FD_USING_GCC),1)
include config/x86-64-gcc-flags.mk
	else ifeq ($(FD_USING_CLANG),1)
include config/x86-64-clang-flags.mk
include config/with-clang.mk
	endif
include config/with-libmicrohttp.mk
endif
