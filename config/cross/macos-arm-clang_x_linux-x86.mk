BASEDIR:=build-cross

CPPFLAGS:=
CPPFLAGS+=-target x86_64-linux-gnu
CPPFLAGS+=--sysroot=./opt/cross/$(CROSS)
CPPFLAGS+=-nostdinc
CPPFLAGS+=-isystem ./opt/cross/$(CROSS)/usr/include
CPPFLAGS+=-isystem ./opt/cross/$(CROSS)/usr/lib/clang/21/include

CROSS:=macos-arm-clang_x_linux-x86
OPT:=./opt/cross/$(CROSS)/opt
LLVM_PREFIX:=$(shell brew --prefix llvm)
CC:=$(LLVM_PREFIX)/bin/clang
CXX:=$(LLVM_PREFIX)/bin/clang++
LD:=$(LLVM_PREFIX)/bin/clang++
LDFLAGS+=-target x86_64-linux-gnu
LDFLAGS+=--sysroot=./opt/cross/$(CROSS)
LDFLAGS+=--ld-path=$(shell brew --prefix lld)/bin/ld.lld
AR:=$(LLVM_PREFIX)/bin/llvm-ar
RANLIB:=$(LLVM_PREFIX)/bin/llvm-ranlib
AWK:=gawk
GREP:=ggrep
FIND:=gfind
UNAME:=Linux
