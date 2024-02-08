FD_HAS_FUZZ:=1

ifndef AFL_LIB
$(error AFL_LIB is not set. Please point it to your installation dir. E.g.: /usr/local/lib/afl ...)
endif

CPPFLAGS+=-fno-omit-frame-pointer
CPPFLAGS+=-fsanitize=fuzzer-no-link
CPPFLAGS+=-fsanitize-coverage=trace-pc-guard

LDFLAGS+=-fsanitize-coverage=trace-pc-guard
LDFLAGS_FUZZ+=$(AFL_LIB)/afl-compiler-rt.o $(AFL_LIB)/libAFLDriver.a
