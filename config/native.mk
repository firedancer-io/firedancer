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

FD_HAS_DOUBLE:=1
CPPFLAGS+=-DFD_HAS_DOUBLE=1
$(call map-define,FD_HAS_ALLOCA, __linux__)
$(call map-define,FD_HAS_THREADS, __linux__)
$(call map-define,FD_HAS_OPENSSL, __linux__)
$(call map-define,FD_HAS_X86, __x86_64__)

ifeq ($(FD_HAS_THREADS),1)
include config/with-threads.mk
endif

ifeq ($(FD_HAS_OPENSSL),1)
include config/with-openssl.mk
endif

ifeq ($(FD_HAS_X86),1)
include config/x86-64-flags.mk
	ifeq ($(FD_USING_GCC),1)
include config/x86-64-gcc-flags.mk
	else ifeq ($(FD_USING_CLANG),1)
include config/x86-64-clang-flags.mk
include config/with-clang.mk
	endif
endif
