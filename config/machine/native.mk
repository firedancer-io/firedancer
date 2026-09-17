ifneq ($(CROSS),)
$(error "native build not supported when cross-compiling.  Try setting MACHINE=linux_clang_zen2")
endif

CC?=gcc
BASEDIR?=build
BUILDDIR?=native/$(notdir $(CC))

# compiler and platform features from the predefined macros of one $(CC) -E -dM run;
# native-def is non-empty when "#define <name> " occurs, native-val is the word after
FD_NATIVE_FLAGS:=$(if $(filter aarch64% arm64%,$(MAKE_HOST)),-mcpu=native,-march=native -mtune=native)
FD_NATIVE_DEFS:=$(shell $(CC) $(FD_NATIVE_FLAGS) -E -dM -x c /dev/null)
hash:=\#
native-def = $(filter @%,$(subst $(hash)define $(1) ,@,$(FD_NATIVE_DEFS)))
native-val = $(patsubst @%,%,$(call native-def,$(1)))

ifneq ($(call native-def,__clang__),)
FD_USING_CLANG:=1
FD_COMPILER_MAJOR_VERSION:=$(call native-val,__clang_major__)
FD_COMPILER_VERSION:=$(FD_COMPILER_MAJOR_VERSION).$(call native-val,__clang_minor__).$(call native-val,__clang_patchlevel__)
endif
ifneq ($(call native-def,__GNUC__),)
FD_IS_GNU:=1
ifndef FD_USING_CLANG
FD_COMPILER_MAJOR_VERSION:=$(call native-val,__GNUC__)
FD_COMPILER_VERSION:=$(FD_COMPILER_MAJOR_VERSION).$(call native-val,__GNUC_MINOR__).$(call native-val,__GNUC_PATCHLEVEL__)
endif
endif

# feature:macro, in CPPFLAGS_NATIVE order
FD_NATIVE_FEATURES:=FD_HAS_SHANI:__SHA__ FD_HAS_INT128:__SIZEOF_INT128__ FD_HAS_ALLOCA:__linux__ FD_HAS_THREADS:__linux__ FD_HAS_X86:__x86_64__ FD_HAS_SSE:__SSE4_2__ FD_HAS_AVX:__AVX2__ FD_HAS_GFNI:__GFNI__ FD_IS_X86_64:__x86_64__ FD_HAS_AESNI:__AES__ FD_IS_ARM:__aarch64__ FD_HAS_NEON:__ARM_NEON FD_HAS_SVE2:__ARM_FEATURE_SVE2 FD_HAS_ARM_SHA256:__ARM_FEATURE_SHA2 FD_HAS_ARM_SHA512:__ARM_FEATURE_SHA512
# GCC < 10 does not fully support AVX512
ifeq ($(and $(FD_IS_GNU),$(if $(FD_USING_CLANG),,1),$(filter 0 1 2 3 4 5 6 7 8 9,$(FD_COMPILER_MAJOR_VERSION))),)
FD_NATIVE_FEATURES+=FD_HAS_AVX512:__AVX512IFMA__
endif
FD_NATIVE_HAS:=$(foreach f,$(FD_NATIVE_FEATURES),$(if $(call native-def,$(lastword $(subst :, ,$(f)))),$(firstword $(subst :, ,$(f)))))
$(foreach v,$(FD_NATIVE_HAS),$(eval $(v):=1))
FD_HAS_DOUBLE:=1
CPPFLAGS_NATIVE:=$(FD_NATIVE_FLAGS) -DFD_HAS_DOUBLE=1 $(foreach v,$(FD_NATIVE_HAS),-D$(v)=1)

# the triple $(CC) -dumpfullversion prints: base.mk need not probe
CC_VERSION:=$(or $(FD_COMPILER_VERSION),unknown)
CC_VERSION_OF:=$(CC)

ifeq ($(FD_IS_GNU),1)
    ifneq ($(FD_USING_CLANG),1)
        FD_USING_GCC := 1
    endif
endif

# Ban broken compilers
ifdef FD_USING_GCC
ifeq ($(FD_COMPILER_VERSION),15.2.0)
$(error Your compiler GCC 15.2.0 is broken (https://gcc.gnu.org/bugzilla/show_bug.cgi?id=123002). Please upgrade GCC or recompile with make CC=clang)
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

ifdef FD_IS_ARM
include config/extra/with-arm.mk
endif
