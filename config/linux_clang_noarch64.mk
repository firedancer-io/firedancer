BUILDDIR?=linux/clang/noarch64

include config/base.mk
include config/with-clang.mk
include config/with-debug.mk
include config/with-brutality.mk
include config/with-optimization.mk
include config/with-threads.mk

CPPFLAGS+=-DFD_HAS_DOUBLE=1 -DFD_HAS_ALLOCA=1

FD_HAS_DOUBLE:=1
FD_HAS_ALLOCA:=1

