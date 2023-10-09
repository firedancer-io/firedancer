CC:=gcc
CXX:=g++
LD:=g++

# See with-clang.mk FD_USING_CLANG for behavior.  FD_USING_GCC and
# FD_USING_CLANG should not be both set simultaneously

CPPFLAGS+=-DFD_USING_GCC=1

ifneq ($(EMACS),1)
CPPFLAGS+=-fdiagnostics-color=always
endif

FD_USING_GCC:=1

