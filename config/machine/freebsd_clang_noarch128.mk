BUILDDIR:=freebsd/clang/noarch128

include config/base.mk
include config/extra/with-clang.mk
include config/extra/with-debug.mk
include config/extra/with-brutality.mk
include config/extra/with-optimization.mk
include config/extra/with-hosted.mk

CPPFLAGS+=-DFD_HAS_INT128=1 -DFD_HAS_DOUBLE=1 -DFD_HAS_ALLOCA=1

# Remove this when we support FD_HAS_THREADS for FreeBSD
CPPFLAGS+=-DFD_HAS_ATOMIC=1

LDFLAGS+=-pthread

FD_HAS_INT128:=1
FD_HAS_DOUBLE:=1
FD_HAS_ALLOCA:=1
FD_HAS_ATOMIC:=1

