CPPFLAGS+=-mfpmath=sse -falign-functions=32

ifdef FD_USING_GCC
CPPFLAGS+=-mbranch-cost=5 -falign-jumps=32 -falign-labels=32 -falign-loops=32
endif

# -falign-functions since Clang/LLVM 7
# -falign-loops     since Clang/LLVM 13
