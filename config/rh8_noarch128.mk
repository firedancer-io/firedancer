BUILDDIR:=rh8/noarch128

include config/base.mk
include config/with-debug.mk
include config/with-brutality.mk
include config/with-optimization.mk
include config/with-threads.mk

CPPFLAGS+=-DFD_HAS_INT128=1 -DFD_HAS_DOUBLE=1

