BUILDDIR?=linux/gcc/zen5

include config/base.mk
include config/extra/with-gcc.mk
include config/extra/with-x86-64.mk
include config/extra/with-debug.mk
include config/extra/with-security.mk
include config/extra/with-brutality.mk
include config/extra/with-optimization.mk
include config/extra/with-threads.mk

# GCC 8 (Firedancer's minimum supported GCC version) only supports znver1.
ifeq ($(shell $(CC) -dumpversion),8)
CPPFLAGS+=-march=znver1 -mtune=znver1
else

# GCC 14+ support zen5.
ifeq ($(shell test `$(CC) -dumpversion | cut -d. -f1` -ge 14 && echo yes),yes)
CPPFLAGS+=-march=znver5 -mtune=znver5
else
$(error Unsupported GCC version $(shell $(CC) -dumpversion). Only GCC 14+ is supported for zen5.)
endif
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
