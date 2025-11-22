CROSS:=wasi
OPT:=./opt/cross/$(CROSS)/opt
LLVM_PREFIX:=./opt/cross/$(CROSS)/wasi-sdk/build/install
CC:=$(LLVM_PREFIX)/bin/clang
CXX:=$(LLVM_PREFIX)/bin/clang++
LD:=$(LLVM_PREFIX)/bin/clang++
AR:=$(LLVM_PREFIX)/bin/llvm-ar
RANLIB:=$(LLVM_PREFIX)/bin/llvm-ranlib
UNAME:=WASI

CPPFLAGS:=
CPPFLAGS+=--target=wasm64-unknown-unknown
CPPFLAGS+=--sysroot=./opt/cross/$(CROSS)/share/wasi-sysroot
