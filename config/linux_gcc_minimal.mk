BUILDDIR:=linux/gcc/minimal

include config/base.mk
include config/with-gcc.mk
include config/with-debug.mk
include config/with-brutality.mk
include config/with-optimization.mk
include config/with-hosted.mk

