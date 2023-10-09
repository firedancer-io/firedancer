FD_HAS_MAIN:=0
CPPFLAGS+=-fno-omit-frame-pointer

CPPFLAGS+=-fsanitize=fuzzer-no-link
LDFLAGS+=-fsanitize=fuzzer
