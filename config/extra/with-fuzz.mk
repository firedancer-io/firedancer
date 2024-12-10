include config/extra/with-fuzz-stubs.mk

FD_HAS_FUZZ:=1

FD_EQVOC_USE_HANDHOLDING:=1
FD_FORKS_USE_HANDHOLDING:=1
FD_GHOST_USE_HANDHOLDING:=1
FD_SCRATCH_USE_HANDHOLDING:=1
FD_TOWER_USE_HANDHOLDING:=1
FD_TXN_HANDHOLDING:=1

CPPFLAGS+=-fno-omit-frame-pointer
CPPFLAGS+=-fsanitize=fuzzer-no-link
CPPFLAGS+=-fsanitize-coverage=inline-8bit-counters

LDFLAGS+=-fsanitize-coverage=inline-8bit-counters
LDFLAGS_FUZZ+=-fsanitize=fuzzer
