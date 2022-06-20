BUILDDIR:=rh8/x86_64

include config/base.mk
include config/with-debug.mk
include config/with-brutality.mk
include config/with-optimization.mk
include config/with-threads.mk

CPPFLAGS+=-march=icelake-server -mfpmath=sse -DFD_HAS_INT128=1 -DFD_HAS_DOUBLE=1 -DFD_HAS_ALLOCA=1 -DFD_HAS_X86=1
LDFLAGS+=-lnuma

