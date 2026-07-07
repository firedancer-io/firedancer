BASEDIR?=build
ifneq ($(BUILDDIR1),)
BUILDDIR:=$(BUILDDIR1)
endif

VERBOSE?=0
OPT?=opt
SHELL:=bash
CPPFLAGS:=-isystem ./$(OPT)/include
RUSTFLAGS:=-C force-frame-pointers=yes
CFLAGS=-std=c17 -fwrapv
CXXFLAGS=-std=c++17
LDFLAGS:=-lm -ldl -L./$(OPT)/lib
LDFLAGS_EXE:=
LDFLAGS_SO:=-shared
AR:=ar
ARFLAGS:=rcs
RANLIB:=ranlib
CP:=cp -p
RM:=rm -f
PATCH:=patch
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
CXX?=g++
LD?=$(CXX)

# LLVM toolchain
LLVM_COV?=llvm-cov
LLVM_PROFDATA?=llvm-profdata

# C++ support (libstdc++ and default exception handler)
#FD_HAS_CXX:=1

# Rust
RUST_PROFILE=debug

# lcov
LCOV=lcov
GENHTML=genhtml
# newer versions of genhtml will require '-ignore-errors unmapped'

# Parameters passed to libFuzzer tests
FUZZFLAGS:=-max_total_time=600 -timeout=10 -runs=10

# Obtain compiler version so that decisions can be made on disabling/enabling
# certain flags
CC_MAJOR_VERSION:=$(shell $(CC) -dumpversion | cut -f1 -d.)

# Default _FORTIFY_SOURCE level
FORTIFY_SOURCE?=2

# Prefer LLD when available
ifeq ($(CROSS),)
ifneq ($(shell command -v ld.lld 2>/dev/null),)
ifeq ($(shell test $(CC_MAJOR_VERSION) -ge 9 2>/dev/null && echo ok),ok)
LDFLAGS+=-fuse-ld=lld
endif
endif
endif

ifneq ($(CROSS),)
include config/cross/$(CROSS).mk
endif
