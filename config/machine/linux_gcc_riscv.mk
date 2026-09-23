BUILDDIR:=linux/gcc/riscv

include config/extra/with-gcc-pre.mk
include config/base.mk
include config/extra/with-gcc.mk

CPPFLAGS:=
LDFLAGS:=-lm

ifneq ($(shell uname -m),riscv64)
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

# Vector SHA-2 requires Zvkb/Zvknhb; Ed25519 uses full V multiply-high.
# All vector backends require VLEN >= 128.  Retain Zbb scalar rotates.
CPPFLAGS+=-march=rv64gcv_zbb_zvkb_zvknhb_zvl128b
CPPFLAGS+=-DFD_HAS_INT128=1 -DFD_HAS_DOUBLE=1 -DFD_HAS_ALLOCA=1 -DFD_HAS_RISCV=1 -DFD_HAS_RISCV_SHA256=1 -DFD_HAS_RISCV_SHA512=1 -DFD_HAS_RISCV_ED25519=$(FD_HAS_RISCV_ED25519)

FD_HAS_RISCV:=1
FD_HAS_RISCV_SHA256:=1
FD_HAS_RISCV_SHA512:=1
# Override on the make command line for a scalar/RVV field-code comparison.
FD_HAS_RISCV_ED25519?=1
FD_ARCH_SUPPORTS_SANDBOX:=1

FD_HAS_INT128:=1
FD_HAS_DOUBLE:=1
FD_HAS_ALLOCA:=1
