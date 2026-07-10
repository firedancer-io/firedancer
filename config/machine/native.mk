ifneq ($(CROSS),)
$(error "native build not supported when cross-compiling.  Try setting MACHINE=linux_clang_zen2")
endif

CC?=gcc
BASEDIR?=build
BUILDDIR?=native/$(notdir $(CC))

# Detect compiler and platform features
FD_NATIVE_CONFIG:=$(BASEDIR)/$(BUILDDIR)/config.mk
_:=$(shell config/machine/native_config.sh $(FD_NATIVE_CONFIG) $(CC))
include $(FD_NATIVE_CONFIG)
$(FD_NATIVE_CONFIG):;@:

ifeq ($(FD_IS_GNU),1)
    ifneq ($(FD_USING_CLANG),1)
        FD_USING_GCC := 1
    endif
endif

ifdef FD_USING_GCC
  LD?=$(CC)
  include config/base.mk
include config/extra/with-gcc.mk
else ifdef FD_USING_CLANG
  LD?=$(CC)
  include config/base.mk
include config/extra/with-clang.mk
endif

RUSTFLAGS+=-C target-cpu=native
CPPFLAGS+=$(CPPFLAGS_NATIVE)

include config/extra/with-brutality.mk
include config/extra/with-optimization.mk
include config/extra/with-debug.mk
include config/extra/with-security.mk

ifdef FD_HAS_THREADS
include config/extra/with-threads.mk
endif

ifdef FD_IS_X86_64
include config/extra/with-x86-64.mk
endif
