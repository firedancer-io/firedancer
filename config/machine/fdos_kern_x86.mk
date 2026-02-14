# Self-hosted x86 environment, for use as an operating system kernel

BUILDDIR:=fdos/kern/x86_64
include config/machine/bare_clang_x86_64.mk

ifeq ($(wildcard opt/cross/x86/include/stdlib.h),)
$(error Embedded libc not found. Run ./deps.sh +embedded)
endif

CPPFLAGS+=\
  -isystem opt/cross/x86/include \
  -isystem "$(shell $(CC) -print-resource-dir)/include" \
  -nostdinc

FD_FDOS_KERN:=1
CPPFLAGS+=-DFD_FDOS_KERN=1
