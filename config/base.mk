SHELL:=bash
CPPFLAGS:=-I./opt/include
CC:=gcc
CFLAGS:=-std=c17
CXX:=g++
CXXFLAGS:=-std=c++17
LD:=g++
LDFLAGS:=-L./opt/lib -lm -ldl
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

### eBPF compiler configuration

# Clang is the only supported eBPF compiler for now
EBPF_CC:=clang
EBPF_CFLAGS:=-std=c17

# Always cross-compile to eBPF
EBPF_CPPFLAGS+=-I./opt/include -target bpf -O2

# Some versions of Clang attempt to build with stack protection
# which is not supported for the eBPF target -- the kernel verifier
# provides such safety features.
EBPF_CPPFLAGS+=-fno-stack-protector

