FD_HAS_MAIN:=0
FD_HAS_FUZZ:=1

CPPFLAGS+=-DFD_HAS_FUZZ=1
CPPFLAGS+=-fno-omit-frame-pointer
CPPFLAGS+=-fsanitize=fuzzer-no-link

LDFLAGS+=-fsanitize=fuzzer
