BASEDIR?=build
ifneq ($(BUILDDIR1),)
BUILDDIR:=$(BUILDDIR1)
endif

VERBOSE?=0
CPPFLAGS:=
RUSTFLAGS:=-C force-frame-pointers=yes
CFLAGS=-std=c17 -fwrapv
LDFLAGS:=-lm -ldl
LDFLAGS_EXE:=
LDFLAGS_SO:=-shared
AR:=ar
# thin archives; BSD/cctools ar (macOS) has no T (it truncates names)
ARFLAGS:=$(if $(findstring darwin,$(MAKE_HOST)),rcs,rcsT)
RANLIB:=ranlib
CP:=cp -p
RM:=rm -f
MKDIR:=mkdir -p
RMDIR:=rm -rf
TOUCH:=touch
AWK:=awk
GREP:=grep
SED:=sed
FIND:=find
SCRUB:=$(FIND) . -type f -name "*~" -o -name "\#*" | xargs $(RM)
DATE:=date
CAT:=cat
CBMC?=cbmc

# Default compiler configuration, if not already set
CC?=gcc
LD?=$(CC)

# LLVM toolchain
LLVM_COV?=llvm-cov
LLVM_PROFDATA?=llvm-profdata

# Rust
RUST_PROFILE=debug

# lcov
LCOV=lcov
GENHTML=genhtml
# newer versions of genhtml will require '-ignore-errors unmapped'

# Parameters passed to libFuzzer tests
FUZZFLAGS:=-max_total_time=600 -timeout=10 -runs=10

# $(call which,name): first executable on PATH; a name with a slash resolves as-is
which = $(if $(findstring /,$(1)),$(1),$(shell command -v $(1) 2>/dev/null))

# Compiler version keys the default build dir and gates version-specific
# flags.
cc-version = $(or $(shell $(1) -dumpfullversion -dumpversion 2>/dev/null | head -1),unknown)
CC_VERSION:=$(call cc-version,$(CC))
CC_VERSION_OF:=$(CC)
CC_MAJOR_VERSION:=$(firstword $(subst ., ,$(filter-out unknown,$(CC_VERSION))))

# Default _FORTIFY_SOURCE level
FORTIFY_SOURCE?=2

# Prefer LLD when available
ifeq ($(CROSS),)
ifneq ($(call which,ld.lld),)
ifneq ($(CC_MAJOR_VERSION),)
ifeq ($(filter 0 1 2 3 4 5 6 7 8,$(CC_MAJOR_VERSION)),)
LDFLAGS+=-fuse-ld=lld
endif
endif
endif
endif

ifneq ($(CROSS),)
include config/cross/$(CROSS).mk
endif
