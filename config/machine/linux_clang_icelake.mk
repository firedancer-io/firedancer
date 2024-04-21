BUILDDIR?=linux/clang/icelake

include config/base.mk
include config/extra/with-security.mk
include config/extra/with-clang.mk
include config/extra/with-x86-64.mk
include config/extra/with-debug.mk
include config/extra/with-brutality.mk
include config/extra/with-optimization.mk
include config/extra/with-threads.mk
include config/extra/with-ucontext.mk
include config/extra/with-openssl.mk
include config/extra/with-zstd.mk
include config/extra/with-secp256k1.mk
include config/extra/with-rocksdb.mk
include config/extra/with-libff.mk
include config/extra/with-libmicrohttp.mk

# Clang sadly doesn't support important optimizations.  This practically
# limits clang usage to code hygiene usage for the time being.  Here,
# ideally would do:
#
# -falign-functions=32 -falign-jumps=32 -falign-labels=32 -falign-loops=32
# -mbranch-cost=5

CPPFLAGS+=-fomit-frame-pointer -march=icelake-server -mtune=icelake-server -mfpmath=sse \
	  -DFD_HAS_INT128=1 -DFD_HAS_DOUBLE=1 -DFD_HAS_ALLOCA=1 -DFD_HAS_X86=1 -DFD_HAS_SSE=1 -DFD_HAS_AVX=1 \
	  -DFD_HAS_SHANI=1 -DFD_HAS_GFNI=1 -DFD_HAS_AESNI=1 -DFD_HAS_AVX512=1

FD_HAS_INT128:=1
FD_HAS_DOUBLE:=1
FD_HAS_ALLOCA:=1
FD_HAS_X86:=1
FD_HAS_SSE:=1
FD_HAS_AVX:=1
FD_HAS_SHANI:=1
FD_HAS_GFNI:=1
FD_HAS_AESNI:=1
FD_HAS_AVX512:=1
