BUILDDIR:=linux/gcc/native

include config/base.mk
include config/with-hosted.mk
include config/with-gcc.mk
include config/with-debug.mk
include config/with-brutality.mk
include config/with-optimization.mk
include config/with-threads.mk
include config/with-native.mk

ifdef FD_USING_GCC
ifdef FD_HAS_X86
# see linux_gcc_x86_64
CPPFLAGS+=-falign-functions=32 -falign-jumps=32 -falign-labels=32 -falign-loops=32 -mbranch-cost=5
endif
endif

