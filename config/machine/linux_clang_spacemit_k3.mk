BUILDDIR:=linux/clang/spacemit_k3

include config/extra/with-clang-pre.mk
include config/base.mk
include config/extra/with-clang.mk

CPPFLAGS:=
LDFLAGS:=-lm

ifneq ($(shell uname -m),riscv64)
CROSS=1
endif

ifeq ($(CROSS),1)
TARGET?=riscv64-linux-gnu
CPPFLAGS+=-target $(TARGET)
LDFLAGS+=-target $(TARGET)
endif

include config/extra/with-brutality.mk
include config/extra/with-optimization.mk
include config/extra/with-debug.mk
include config/extra/with-security.mk
include config/extra/with-threads.mk

CPPFLAGS+=-mcpu=spacemit-x100
CPPFLAGS+=-DFD_HAS_INT128=1 -DFD_HAS_DOUBLE=1 -DFD_HAS_ALLOCA=1 -DFD_HAS_RISCV=1

FD_HAS_RISCV:=1
FD_ARCH_SUPPORTS_SANDBOX:=1

FD_HAS_INT128:=1
FD_HAS_DOUBLE:=1
FD_HAS_ALLOCA:=1
