BUILDDIR?=linux/gcc/zen5

include config/base.mk
include config/extra/with-gcc.mk
include config/extra/with-x86-64.mk
include config/extra/with-debug.mk
include config/extra/with-security.mk
include config/extra/with-brutality.mk
include config/extra/with-optimization.mk
include config/extra/with-threads.mk

# GCC 14+ support zen5, however, 15 has the optimizations.
ifeq ($(shell test `$(CC) -dumpversion | cut -d. -f1` -ge 15 && echo yes),yes)
CPPFLAGS+=-march=znver5 -mtune=znver5
else
$(error Unsupported GCC version $(shell $(CC) -dumpversion). Only GCC 15+ is fully supported for zen5.)
endif


CPPFLAGS+=\
  -DFD_HAS_INT128=1 \
  -DFD_HAS_DOUBLE=1 \
  -DFD_HAS_ALLOCA=1 \
  -DFD_HAS_X86=1 \
  -DFD_HAS_SSE=1 \
  -DFD_HAS_AVX=1 \
  -DFD_HAS_SHANI=1 \
  -DFD_HAS_AESNI=1 \
  -DFD_HAS_AVX512=1 \
  -DFD_HAS_GFNI=1

FD_HAS_INT128:=1
FD_HAS_DOUBLE:=1
FD_HAS_ALLOCA:=1
FD_HAS_X86:=1
FD_HAS_SSE:=1
FD_HAS_AVX:=1
FD_HAS_SHANI:=1
FD_HAS_AESNI:=1
FD_HAS_AVX512:=1
FD_HAS_GFNI:=1
