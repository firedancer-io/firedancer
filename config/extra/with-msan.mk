FD_HAS_MSAN:=1
CPPFLAGS+=-DFD_HAS_MSAN=1

CPPFLAGS+=-fsanitize=memory -fsanitize-memory-track-origins

LDFLAGS+=-fsanitize=memory -fsanitize-memory-track-origins
