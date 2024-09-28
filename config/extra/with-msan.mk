FD_HAS_MSAN:=1
CPPFLAGS+=-DFD_HAS_MSAN=1

CPPFLAGS+=-fsanitize=memory
#CPPFLAGS+=-fsanitize-memory-track-origins

LDFLAGS+=-fsanitize=memory
#LDFLAGS+=-fsanitize-memory-track-origins

include config/extra/with-libcxx.mk
