BASEDIR:=build-cross

# Linux x86-64 host, clang, targeting aarch64 Linux.  Needs a glibc
# sysroot for the target in $(AARCH64_SYSROOT) (e.g. the Ubuntu
# libc6-dev-arm64-cross + libgcc-*-dev-arm64-cross packages extracted
# into a directory) and either mold or lld.  Binaries run under
# qemu-aarch64 -L $(AARCH64_SYSROOT).

CROSS:=linux-x86-clang_x_linux-aarch64
AARCH64_SYSROOT?=/opt/cross/aarch64-linux-gnu
UNAME:=Linux

CPPFLAGS:=
CPPFLAGS+=-target aarch64-linux-gnu
CPPFLAGS+=--sysroot=$(AARCH64_SYSROOT)
CPPFLAGS+=--gcc-toolchain=$(AARCH64_SYSROOT)/usr
LDFLAGS+=-target aarch64-linux-gnu
LDFLAGS+=--sysroot=$(AARCH64_SYSROOT)
LDFLAGS+=--gcc-toolchain=$(AARCH64_SYSROOT)/usr
ifneq ($(call which,mold),)
LDFLAGS+=-fuse-ld=mold
else
LDFLAGS+=-fuse-ld=lld
endif
