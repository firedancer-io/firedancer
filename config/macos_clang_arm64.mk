BUILDDIR:=macos/clang/arm64

include config/base.mk
include config/with-macos.mk
include config/with-clang.mk
include config/with-debug.mk
include config/with-brutality.mk
include config/with-optimization.mk
include config/with-threads.mk

CPPFLAGS+=-march=native -mcpu=apple-m1 \
	  -DFD_HAS_INT128=1 -DFD_HAS_DOUBLE=1 -DFD_HAS_ALLOCA=1 -DFD_HAS_ARM=1

FD_HAS_INT128:=1
FD_HAS_DOUBLE:=1
FD_HAS_ALLOCA:=1
FD_HAS_ARM:=1
