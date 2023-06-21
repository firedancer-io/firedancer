include config/linux_clang_x86_64.mk
include config/with-ffi.mk
BUILDDIR:=linux/clang/x86_64_asan

FD_HAS_ASAN:=1
CPPFLAGS+=-DFD_HAS_ASAN=1

CPPFLAGS+=-fsanitize=address
LDFLAGS+=-fsanitize=address

