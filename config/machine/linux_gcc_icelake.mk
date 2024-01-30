BUILDDIR?=linux/gcc/icelake

include config/base.mk
include config/extra/with-security.mk
include config/extra/with-gcc.mk
include config/extra/with-x86-64.mk
include config/extra/with-debug.mk
include config/extra/with-brutality.mk
include config/extra/with-optimization.mk
include config/extra/with-threads.mk
include config/extra/with-ucontext.mk
include config/extra/with-openssl.mk
include config/extra/with-zstd.mk

CPPFLAGS+=-march=icelake-server -mtune=icelake-server \
	  -DFD_HAS_INT128=1 -DFD_HAS_DOUBLE=1 -DFD_HAS_ALLOCA=1 -DFD_HAS_X86=1 -DFD_HAS_SSE=1 -DFD_HAS_AVX=1 \
		-DFD_HAS_SHANI=1 -DFD_HAS_GFNI=1 -DFD_HAS_AESNI=1

FD_HAS_INT128:=1
FD_HAS_DOUBLE:=1
FD_HAS_ALLOCA:=1
FD_HAS_X86:=1
FD_HAS_SSE:=1
FD_HAS_AVX:=1
FD_HAS_SHANI:=1
FD_HAS_GFNI:=1
FD_HAS_AESNI:=1
