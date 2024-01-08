BUILDDIR?=linux/clang/x86_64

include config/base.mk
include config/extra/with-security.mk
include config/extra/with-clang.mk
include config/extra/with-x86-64.mk
include config/extra/with-debug.mk
include config/extra/with-brutality.mk
include config/extra/with-optimization.mk
include config/extra/with-threads.mk
include config/extra/with-openssl.mk
include config/extra/with-zstd.mk

# Clang sadly doesn't support important optimizations.  This practically
# limits clang usage to code hygiene usage for the time being.  Here,
# ideally would do:
#
# -falign-functions=32 -falign-jumps=32 -falign-labels=32 -falign-loops=32
# -mbranch-cost=5

CPPFLAGS+=-march=haswell -mtune=skylake
CPPFLAGS+=-DFD_HAS_INT128=1 -DFD_HAS_DOUBLE=1 -DFD_HAS_ALLOCA=1 -DFD_HAS_X86=1 -DFD_HAS_SSE=1 -DFD_HAS_AVX=1

FD_HAS_INT128:=1
FD_HAS_DOUBLE:=1
FD_HAS_ALLOCA:=1
FD_HAS_X86:=1
FD_HAS_SSE:=1
FD_HAS_AVX:=1

