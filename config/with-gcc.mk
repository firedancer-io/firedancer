CC:=gcc
CXX:=g++
LD:=g++

# See with-clang.mk FD_USING_CLANG for behavior.  FD_USING_GCC and
# FD_USING_CLANG should not be both set simulateously

CPPFLAGS+=-DFD_USING_GCC=1 -fdiagnostics-color=always

FD_USING_GCC:=1

