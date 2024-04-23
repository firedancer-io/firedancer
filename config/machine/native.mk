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

ifdef FD_USING_GCC
include config/base.mk
	CC:=gcc
	CXX:=g++
	LD:=g++
  FD_COMPILER_MAJOR_VERSION:=$(shell echo | $(CC) -march=native -E -dM - | grep __GNUC__ | awk '{print $$3}')
include config/extra/with-gcc.mk
else ifdef FD_USING_CLANG
include config/base.mk
	CC=clang
	CXX=clang++
	LD=clang++
  FD_COMPILER_MAJOR_VERSION:=$(shell echo | $(CC) -march=native -E -dM - | grep __clang_major__ |  awk '{print $$3}')
include config/extra/with-clang.mk
endif

BUILDDIR?=native/$(CC)
CPPFLAGS+=-march=native -mtune=native
RUSTFLAGS+=-C target-cpu=native

include config/extra/with-brutality.mk
include config/extra/with-optimization.mk
include config/extra/with-debug.mk
include config/extra/with-security.mk

$(call map-define,FD_HAS_SHANI, __SHA__)
$(call map-define,FD_HAS_INT128, __SIZEOF_INT128__)
FD_HAS_DOUBLE:=1
CPPFLAGS+=-DFD_HAS_DOUBLE=1
$(call map-define,FD_HAS_ALLOCA, __linux__)
$(call map-define,FD_HAS_THREADS, __linux__)
$(call map-define,FD_HAS_OPENSSL, __linux__)
$(call map-define,FD_HAS_X86, __x86_64__)
$(call map-define,FD_HAS_SSE, __SSE4_2__)
$(call map-define,FD_HAS_AVX, __AVX2__)
$(call map-define,FD_HAS_GFNI, __GFNI__)
$(call map-define,FD_IS_X86_64, __x86_64__)
$(call map-define,FD_HAS_AESNI, __AES__)

# Older version of GCC (<10) don't fully support AVX512, so we disable
# it in those cases. Older versions of Clang (<8) don't support it
# either, but Firedancer doesn't support those versions.
ifdef FD_USING_GCC
       ifeq ($(shell test $(FD_COMPILER_MAJOR_VERSION) -lt 10 && echo 1),1)
               FD_HAS_AVX512:=
               FD_HAS_AVX512_MESSAGE:=(Disabled because GCC version $(FD_COMPILER_MAJOR_VERSION) not >= 10.0)
       else
# This line cannot be indented properly
$(call map-define,FD_HAS_AVX512, __AVX512IFMA__)
       endif
else ifdef FD_USING_CLANG
$(call map-define,FD_HAS_AVX512, __AVX512IFMA__)
endif

ifdef FD_HAS_THREADS
include config/extra/with-threads.mk
endif

ifdef FD_IS_X86_64
include config/extra/with-x86-64.mk
$(info Using FD_HAS_SSE=$(FD_HAS_SSE))
$(info Using FD_HAS_AVX=$(FD_HAS_AVX))
$(info Using FD_HAS_AVX512=$(FD_HAS_AVX512) $(FD_HAS_AVX512_MESSAGE))
$(info Using FD_HAS_GFNI=$(FD_HAS_GFNI))
$(info Using FD_HAS_SHANI=$(FD_HAS_SHANI))
$(info Using FD_HAS_AESNI=$(FD_HAS_AESNI))
endif
