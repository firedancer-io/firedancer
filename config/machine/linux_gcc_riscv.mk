BUILDDIR:=linux/gcc/riscv

include config/base.mk
include config/extra/with-gcc.mk

CPPFLAGS:=
LDFLAGS:=-lm

ifneq ($(shell uname -m),ppc64le)
CROSS=1
endif

ifeq ($(CROSS),1)
CC:=riscv64-linux-gnu-gcc
LD:=riscv64-linux-gnu-gcc
endif

include config/extra/with-brutality.mk
include config/extra/with-optimization.mk
include config/extra/with-debug.mk
include config/extra/with-security.mk
include config/extra/with-threads.mk

CPPFLAGS+=-DFD_HAS_INT128=1 -DFD_HAS_DOUBLE=1 -DFD_HAS_ALLOCA=1

FD_HAS_INT128:=1
FD_HAS_DOUBLE:=1
FD_HAS_ALLOCA:=1
