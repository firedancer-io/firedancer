FD_HAS_FUZZ:=1

CPPFLAGS+=-fno-omit-frame-pointer
CPPFLAGS+=-fsanitize=fuzzer-no-link
CPPFLAGS+=-fsanitize-coverage=inline-8bit-counters
CPPFLAGS+=-DFD_TMPL_USE_HANDHOLDING=1

LDFLAGS+=-fsanitize-coverage=inline-8bit-counters
LDFLAGS_FUZZ+=-fsanitize=fuzzer
