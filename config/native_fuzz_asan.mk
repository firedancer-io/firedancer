CC:=clang
BUILDDIR:=native/fuzz_asan
include config/native.mk
include config/with-ffi.mk

FD_HAS_MAIN:=0
CPPFLAGS+=-fsanitize=fuzzer-no-link
LDFLAGS+=-fsanitize=fuzzer
