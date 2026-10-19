# Note: This probably needs to after machine specific targets otherwise
# the -fomit-frame-pointer that occurs there will be silently override
# the -fno-omit-frame-pointer here.

FD_HAS_ASAN:=1
CPPFLAGS+=-DFD_HAS_ASAN=1

CPPFLAGS+=-fsanitize=address,leak

LDFLAGS+=-fsanitize=address,leak

ifdef FD_USING_GCC
# Eliminate some false errors that pop up with asan is used. Not sure
# why gcc does this, but it is probably a bug. We also need to turn
# off stack protection because it can cause misalignments, due to
# another bug.
CPPFLAGS+=-Wno-stringop-truncation -Wno-array-bounds -Wno-maybe-uninitialized -fno-stack-protector
LDFLAGS+=-fno-stack-protector
# GCC PR 120201: AVX-512 moves can fault on ASan's 32-byte-aligned
# use-after-return fake stack. Fixed in GCC 13.5, 14.5, 15.4 and 16.2.
ifneq ($(filter $(addsuffix .%,0 1 2 3 4 5 6 7 8 9 10 11 12 13.0 13.1 13.2 13.3 13.4 14.0 14.1 14.2 14.3 14.4 15.0 15.1 15.2 15.3 16.0 16.1),$(CC_VERSION)),)
ifneq ($(filter __AVX512F__,$(shell $(CC) $(CPPFLAGS) $(EXTRA_CPPFLAGS) $(CFLAGS) -E -dM -x c /dev/null)),)
CPPFLAGS+=--param=asan-use-after-return=0
endif
endif
endif
