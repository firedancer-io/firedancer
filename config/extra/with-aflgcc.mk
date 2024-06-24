FD_HAS_AFLGCC:=1
CC:=afl-gcc-fast
CXX:=afl-g++-fast
LD:=afl-g++-fast


CPPFLAGS+=-DFD_USING_GCC=1
LDFLAGS+=-static-libgcc

FD_USING_GCC:=1
