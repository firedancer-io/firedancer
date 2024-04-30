FD_HAS_FUZZ:=1

CPPFLAGS+=-fno-omit-frame-pointer
ifeq ($(FD_HAS_AFLGCC),)
  CPPFLAGS+=-fsanitize=fuzzer-no-link
  CPPFLAGS+=-fsanitize-coverage=inline-8bit-counters
  LDFLAGS+=-fsanitize-coverage=inline-8bit-counters
endif
LDFLAGS_FUZZ+=-fsanitize=fuzzer
