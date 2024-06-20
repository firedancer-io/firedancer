CPPFLAGS+=-mfpmath=sse -falign-functions=32

ifdef FD_USING_GCC
CPPFLAGS+=-mbranch-cost=5 -falign-jumps=32 -falign-labels=32 -falign-loops=32
endif

# -falign-functions since Clang/LLVM 7
# -falign-loops     since Clang/LLVM 13

include config/extra/with-ucontext.mk
include config/extra/with-secp256k1.mk
include config/extra/with-zstd.mk
include config/extra/with-openssl.mk
include config/extra/with-rocksdb.mk
