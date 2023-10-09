# Note: This probably needs to after machine specific targets otherwise
# the -fomit-frame-pointer that occurs there will be silently override
# the -fno-omit-frame-pointer here.

FD_HAS_ASAN:=1
CPPFLAGS+=-DFD_HAS_ASAN=1

CPPFLAGS+=-fsanitize=address,leak  -fno-omit-frame-pointer

LDFLAGS+=-fsanitize=address,leak
