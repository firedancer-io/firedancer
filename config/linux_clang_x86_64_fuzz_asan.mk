include config/linux_clang_x86_64.mk
include config/with-ffi.mk
BUILDDIR:=linux/clang/x86_64_fuzz_asan


FD_HAS_ASAN:=1
FD_HAS_MAIN:=0
CPPFLAGS+=-fsanitize=fuzzer-no-link,address
LDFLAGS+=-fsanitize=fuzzer,address

