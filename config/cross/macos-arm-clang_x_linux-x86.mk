BASEDIR:=build-cross

# macOS Homebrew build toolchain

CROSS:=macos-arm-clang_x_linux-x86
OPT:=./opt/cross/$(CROSS)/opt
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

# Configure Clang for cross-compiling

CPPFLAGS:=
CPPFLAGS+=-target x86_64-linux-gnu
CPPFLAGS+=--sysroot=./opt/cross/$(CROSS)
CPPFLAGS+=-nostdinc
CPPFLAGS+=-isystem ./opt/cross/$(CROSS)/usr/include
CPPFLAGS+=-isystem ./opt/cross/$(CROSS)/usr/lib/clang/21/include
LDFLAGS+=-target x86_64-linux-gnu
LDFLAGS+=--sysroot=./opt/cross/$(CROSS)
LDFLAGS+=--ld-path=$(shell brew --prefix lld)/bin/ld.lld

# Dependencies

CPPFLAGS+=-isystem ./opt/cross/$(CROSS)/usr/local/include
LDFLAGS+=-L./opt/cross/$(CROSS)/usr/local/lib

FD_HAS_LIBURING:=1
CFLAGS+=-DFD_HAS_LIBURING=1
LDFLAGS+=-luring

FD_HAS_BZIP2:=1
CFLAGS+=-DFD_HAS_BZIP2=1
LDFLAGS+=-lbz2

FD_HAS_LZ4:=1
CFLAGS+=-DFD_HAS_LZ4=1
LDFLAGS+=-llz4

FD_HAS_ZSTD:=1
CFLAGS+=-DFD_HAS_ZSTD=1
LDFLAGS+=-lzstd

FD_HAS_ROCKSDB:=1
CFLAGS+=-DFD_HAS_ROCKSDB=1
ROCKSDB_LIBS:=-lrocksdb -lsnappy

FD_HAS_SECP256K1:=1
CFLAGS+=-DFD_HAS_SECP256K1=1
LDFLAGS+=-lsecp256k1
