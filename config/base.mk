BASEDIR?=build

OPT?=opt
SHELL:=bash
CPPFLAGS:=-isystem ./$(OPT)/include
RUSTFLAGS:=-C force-frame-pointers=yes
CC:=gcc
CFLAGS=-std=c17 -fwrapv
CXX:=g++
CXXFLAGS=-std=c++17
LD:=g++
LDFLAGS:=-lm -ldl -L./$(OPT)/lib
LDFLAGS_EXE:=
LDFLAGS_SO:=-shared
AR:=ar
ARFLAGS:=rv
RANLIB:=ranlib
CP:=cp -pv
RM:=rm -fv
PATCH:=patch
MKDIR:=mkdir -pv
RMDIR:=rm -rfv
TOUCH:=touch
AWK:=awk
GREP:=grep
SED:=sed
FIND:=find
SCRUB:=$(FIND) . -type f -name "*~" -o -name "\#*" | xargs $(RM)
DATE:=date
CAT:=cat

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

# Obtain compiler version so that decisions can be made on disabling/enabling
# certain flags
CC_MAJOR_VERSION=$(shell $(CC) -dumpversion | cut -f1 -d.)

# Default _FORTIFY_SOURCE level
FORTIFY_SOURCE?=2

ifneq ($(CROSS),)
include config/cross/$(CROSS).mk
endif
