# Self-hosted x86 environment

BUILDDIR?=bare/clang/x86_64

FD_NODEPS:=1
include config/extra/with-clang-pre.mk
include config/base.mk
include config/extra/with-clang.mk
include config/extra/with-x86-64.mk
include config/extra/with-brutality.mk
include config/extra/with-optimization.mk

CPPFLAGS+=-march=x86-64-v2 -mtune=generic
CPPFLAGS+=\
  -DFD_HAS_INT128=1 \
  -DFD_HAS_DOUBLE=1 \
  -DFD_HAS_ALLOCA=1 \
  -DFD_HAS_X86=1

CPPFLAGS+=\
  -DFD_ENV_STYLE=1 \
  -DFD_LOG_STYLE=1 \
  -DFD_IO_STYLE=1

CFLAGS+=\
  --target=x86_64-unknown-elf \
  --no-default-config \
  -ffreestanding \
  -fno-plt \
  -fno-pie \
  -fno-pic \
  -static \
  -fno-common \
  -nostdlib \
  -nostartfiles \
  -nodefaultlibs \
  -mcmodel=kernel \
  -mno-red-zone

FD_HAS_INT128:=1
FD_HAS_DOUBLE:=1
FD_HAS_ALLOCA:=1
FD_HAS_X86:=1
