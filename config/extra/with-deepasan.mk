FD_HAS_ASAN:=1
FD_HAS_DEEPASAN:=1
CPPFLAGS+=-DFD_HAS_ASAN=1 -DFD_HAS_DEEPASAN=1

CPPFLAGS+=-fsanitize=address,leak -fno-omit-frame-pointer

LDFLAGS+=-fsanitize=address,leak

ifdef FD_USING_GCC
# Eliminate some false errors that pop up with asan is used. Not sure
# why gcc does this, but it is probably a bug. We also need to turn
# off stack protection because it can cause misalignments, due to
# another bug.
CPPFLAGS+=-Wno-stringop-truncation -Wno-array-bounds -Wno-maybe-uninitialized -fno-stack-protector
LDFLAGS+=-fno-stack-protector
# gcc PR 120201: on AVX-512 targets, gcc before 13.5, 14.5, 15.4 and
# 16.2 can emit aligned 512-bit moves to locals that the asan
# use-after-return fake stack only aligns to 32 bytes.  Disable
# use-after-return detection for those.
ifneq ($(filter $(addsuffix .%,0 1 2 3 4 5 6 7 8 9 10 11 12 13.0 13.1 13.2 13.3 13.4 14.0 14.1 14.2 14.3 14.4 15.0 15.1 15.2 15.3 16.0 16.1),$(CC_VERSION)),)
ifneq ($(findstring __AVX512F__,$(shell $(CC) $(CPPFLAGS) -E -dM -x c /dev/null)),)
CPPFLAGS+=--param=asan-use-after-return=0
endif
endif
endif
