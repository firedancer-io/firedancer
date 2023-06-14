BUILDDIR:=linux/clang/fuzz_asan
include config/linux_clang_x86_64.mk
include config/with-pic.mk

FD_HAS_MAIN:=0
CPPFLAGS+=-fsanitize=fuzzer-no-link,address
LDFLAGS+=-fsanitize=fuzzer,address

