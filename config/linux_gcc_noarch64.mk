BUILDDIR:=linux/gcc/noarch64

include config/base.mk
include config/with-security.mk
include config/with-gcc.mk
include config/with-debug.mk
include config/with-brutality.mk
include config/with-optimization.mk
include config/with-threads.mk

CPPFLAGS+=-DFD_HAS_DOUBLE=1 -DFD_HAS_ALLOCA=1

FD_HAS_DOUBLE:=1
FD_HAS_ALLOCA:=1

