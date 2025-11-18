BUILDDIR:=macos/clang/m1

include config/base.mk
include config/extra/with-clang.mk
include config/extra/with-debug.mk
include config/extra/with-optimization.mk

# macOS Homebrew build toolchain

LLVM_PREFIX:=$(shell brew --prefix llvm)
CC:=$(LLVM_PREFIX)/bin/clang
CXX:=$(LLVM_PREFIX)/bin/clang++
LD:=$(LLVM_PREFIX)/bin/clang++
AR:=$(LLVM_PREFIX)/bin/llvm-ar
RANLIB:=$(LLVM_PREFIX)/bin/llvm-ranlib
AWK:=gawk
GREP:=ggrep
FIND:=gfind
UNAME:=Linux
CPPFLAGS+=-DFD_HAS_INT128=1 -DFD_HAS_DOUBLE=1 -DFD_HAS_ALLOCA=1

# Remove this when we support FD_HAS_HOSTED for macOS
CPPFLAGS+=-DFD_ENV_STYLE=0 -DFD_IO_STYLE=0 -DFD_LOG_STYLE=0

# Remove this when we support FD_HAS_THREADS for macOS
CPPFLAGS+=-DFD_HAS_ATOMIC=1

CPPFLAGS+=-mcpu=apple-m1  # Requires AppleClang 14

FD_HAS_INT128:=1
FD_HAS_DOUBLE:=1
FD_HAS_ALLOCA:=1
FD_HAS_ATOMIC:=1

