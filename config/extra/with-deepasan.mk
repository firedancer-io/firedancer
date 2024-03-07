FD_HAS_ASAN:=1
FD_HAS_DEEPASAN:=1
CPPFLAGS+=-DFD_HAS_ASAN=1
CFLAGS+=-DFD_HAS_DEEPASAN=1

CPPFLAGS+=-fsanitize=address,leak  -fno-omit-frame-pointer

LDFLAGS+=-fsanitize=address,leak
