BUILDDIR?=linux/gcc/zen2

include config/linux_x86_64_base.mk
include config/with-gcc.mk
include config/with-debug.mk
include config/with-brutality.mk
include config/with-optimization.mk
include config/with-threads.mk
include config/with-openssl.mk

# GCC 8 (Firedancer's minimum supported GCC version) only supports znver1.
ifeq ($(shell $(CC) -dumpversion),8)
CPPFLAGS+=-march=znver1 -mtune=znver1
else
CPPFLAGS+=-march=znver2 -mtune=znver2
endif

CPPFLAGS+=-fomit-frame-pointer \
  -mfpmath=sse \
  -mbranch-cost=5 \
  -DFD_HAS_INT128=1 \
  -DFD_HAS_DOUBLE=1 \
  -DFD_HAS_ALLOCA=1 \
  -DFD_HAS_X86=1 \
  -DFD_HAS_SSE=1 \
  -DFD_HAS_AVX=1 \
  -DFD_HAS_SHANI=1

FD_HAS_INT128:=1
FD_HAS_DOUBLE:=1
FD_HAS_ALLOCA:=1
FD_HAS_X86:=1
FD_HAS_SSE:=1
FD_HAS_AVX:=1
FD_HAS_SHANI:=1
