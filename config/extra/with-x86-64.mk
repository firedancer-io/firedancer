CPPFLAGS+=-mfpmath=sse -falign-functions=32

ifdef FD_USING_GCC
CPPFLAGS+=-mbranch-cost=5 -falign-jumps=32 -falign-labels=32 -falign-loops=32
endif

# Don't attempt to transform vsprtps into vrsqrtps (not IEEE-compliant)
ifdef FD_USING_CLANG
CPPFLAGS+=-Xclang -target-feature -Xclang +fast-vector-fsqrt
endif

# -falign-functions since Clang/LLVM 7
# -falign-loops     since Clang/LLVM 13

include config/extra/with-ucontext.mk
include config/extra/with-secp256k1.mk
include config/extra/with-s2nbignum.mk
include config/extra/with-zstd.mk
include config/extra/with-lz4.mk
include config/extra/with-openssl.mk
include config/extra/with-rocksdb.mk

FD_ARCH_SUPPORTS_SANDBOX:=1
