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
include config/extra/with-secp256k1.mk
include config/extra/with-bz2.mk
include config/extra/with-rocksdb.mk
include config/extra/with-libff.mk
include config/extra/with-libmicrohttp.mk


CPPFLAGS+=-march=icelake-server -mtune=icelake-server \
	  -DFD_HAS_INT128=1 -DFD_HAS_DOUBLE=1 -DFD_HAS_ALLOCA=1 -DFD_HAS_X86=1 -DFD_HAS_SSE=1 -DFD_HAS_AVX=1 \
		-DFD_HAS_SHANI=1 -DFD_HAS_GFNI=1 -DFD_HAS_AESNI=1

FD_COMPILER_MAJOR_VERSION:=$(shell echo | $(CC) -march=native -E -dM - | grep __GNUC__ | awk '{print $$3}')
ifeq ($(shell test $(FD_COMPILER_MAJOR_VERSION) -lt 10 && echo 1),1)
	FD_HAS_AVX512:=
else
	CPPFLAGS+=-DFD_HAS_AVX512=1
	FD_HAS_AVX512:=1
endif

FD_HAS_INT128:=1
FD_HAS_DOUBLE:=1
FD_HAS_ALLOCA:=1
FD_HAS_X86:=1
FD_HAS_SSE:=1
FD_HAS_AVX:=1
FD_HAS_SHANI:=1
FD_HAS_GFNI:=1
FD_HAS_AESNI:=1
