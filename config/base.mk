BASEDIR?=build

SHELL:=bash
CPPFLAGS:=-isystem ./opt/include -DFD_LOG_UNCLEAN_EXIT=1 -DFD_HAS_BACKTRACE=0
CC:=gcc
CFLAGS:=-std=c17
CXX:=g++
CXXFLAGS:=-std=c++17
LD:=g++
LDFLAGS:=-lm -lrt -ldl -L./opt/lib  -Wl,-rpath=$(shell pwd)/opt/lib
AR:=ar
ARFLAGS:=rv
RANLIB:=ranlib
CP:=cp -pv
RM:=rm -fv
PATCH:=patch
MKDIR:=mkdir -pv
RMDIR:=rm -rfv
TOUCH:=touch
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
GENHTML=genhtml
# newer versions of genhtml will require '-ignore-errors unmapped'

# Parameters passed to libFuzzer tests
FUZZFLAGS:=-max_total_time=600 -timeout=10 -runs=10

# Obtain compiler version so that decisions can be made on disabling/enabling
# certain flags
CC_MAJOR_VERSION=$(shell $(CC) -dumpversion | cut -f1 -d.)
