BUILDDIR:=linux/clang/x86_64_asan
include config/linux_clang_x86_64.mk
include config/with-ffi.mk

CPPFLAGS+=-fsanitize=address
LDFLAGS+=-fsanitize=address

