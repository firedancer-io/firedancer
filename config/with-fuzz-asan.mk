include config/with-ffi.mk

FD_HAS_MAIN:=0
CPPFLAGS+=-fsanitize=fuzzer-no-link,address
LDFLAGS+=-fsanitize=fuzzer,address
