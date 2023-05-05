SHELL:=bash
CPPFLAGS:=
CC:=gcc
CFLAGS:=-std=c17
CXX:=g++
CXXFLAGS:=-std=c++17
LD:=g++
LDFLAGS:=-lm
AR:=ar
ARFLAGS:=rv
RANLIB:=ranlib
CP:=cp -pv
RM:=rm -fv
MKDIR:=mkdir -pv
RMDIR:=rm -rfv
SED:=sed
FIND:=find
SCRUB:=$(FIND) . -type f -name "*~" -o -name "\#*" | xargs $(RM)
DATE:=date
CAT:=cat
OBJDUMP:=objdump

# LLVM toolchain
LLVM_COV?=llvm-cov
LLVM_PROFDATA?=llvm-profdata

# lcov
GENHTML=genhtml

# FD_HAS_MAIN: Target supports linking objects with main function.
# If set to 0, programs and unit tests will not be built. This is
# useful for some build configs where a library with a main symbol is
# linked in (e.g. fuzz targets)
FD_HAS_MAIN:=1
