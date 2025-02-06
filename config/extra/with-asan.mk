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
endif
