BUILDDIR:=macos/clang/intel

include config/base.mk
include config/with-clang.mk
include config/with-macos.mk
include config/with-debug.mk
include config/with-brutality.mk
include config/with-optimization.mk
include config/with-threads.mk

CPPFLAGS+=-fomit-frame-pointer -march=haswell -mtune=skylake -mfpmath=sse \
	  -DFD_HAS_INT128=1 -DFD_HAS_DOUBLE=1 -DFD_HAS_ALLOCA=1 -DFD_HAS_X86=1 -DFD_HAS_SSE=1 -DFD_HAS_AVX=1

FD_HAS_INT128:=1
FD_HAS_DOUBLE:=1
FD_HAS_ALLOCA:=1
FD_HAS_X86:=1
FD_HAS_SSE:=1
FD_HAS_AVX:=1

CC:=$(LLVM_DIR)/bin/clang
CXX:=$(LLVM_DIR)/bin/clang++
LD:=$(LLVM_DIR)/bin/clang++
AR:=$(LLVM_DIR)/bin/llvm-ar
RANLIB:=$(LLVM_DIR)/bin/llvm-ranlib
LLVM_COV:=$(LLVM_DIR)/bin/llvm-cov
LLVM_PROFDATA:=$(LLVM_DIR)/bin/llvm-profdata
EBPF_CC:=$(LLVM_DIR)/bin/clang
