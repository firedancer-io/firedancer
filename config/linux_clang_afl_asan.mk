BUILDDIR:=linux/clang/afl_asan

include config/base.mk

CC:=afl-clang-fast
CXX:=afl-clang-fast++
LD:=afl-clang-fast++
FD_USING_CLANG:=1
CPPFLAGS+=-DFD_USING_CLANG=1

include config/with-debug.mk
include config/with-brutality.mk
include config/with-optimization.mk
include config/with-threads.mk

CPPFLAGS+=-fsanitize=fuzzer-no-link,address \
      -march=native -DFD_HAS_INT128=1 -DFD_HAS_DOUBLE=1 -DFD_HAS_ALLOCA=1 -DFD_HAS_X86=1
LDFLAGS+=-fsanitize=fuzzer,address

FD_HAS_INT128:=1
FD_HAS_DOUBLE:=1
FD_HAS_ALLOCA:=1
FD_HAS_X86:=1
FD_HAS_MAIN:=0

