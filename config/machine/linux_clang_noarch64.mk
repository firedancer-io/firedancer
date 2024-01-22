BUILDDIR?=linux/clang/noarch64

include config/base.mk
include config/extra/with-security.mk
include config/extra/with-clang.mk
include config/extra/with-debug.mk
include config/extra/with-brutality.mk
include config/extra/with-optimization.mk
include config/extra/with-threads.mk

CPPFLAGS+=-DFD_HAS_DOUBLE=1 -DFD_HAS_ALLOCA=1

FD_HAS_DOUBLE:=1
FD_HAS_ALLOCA:=1

