CC:=gcc
CXX:=g++
LD:=g++

# See with-clang.mk FD_USING_CLANG for behavior.  FD_USING_GCC and
# FD_USING_CLANG should not be both set simulateously

CPPFLAGS+=-DFD_USING_GCC=1

ifneq ($(EMACS),1)
CPPFLAGS+=-fdiagnostics-color=always
endif

FD_USING_GCC:=1

# Check for GCC version and disable -Wdangling-pointer if we are using 
# gcc 13 as it is giving a false positive 
ifeq "$(CC_MAJOR_VERSION)" "13"
CPPFLAGS+="-Wno-dangling-pointer"
endif

