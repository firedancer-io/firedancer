FD_HAS_MSAN:=1
CPPFLAGS+=-DFD_HAS_MSAN=1

CPPFLAGS+=-fsanitize=memory
#CPPFLAGS+=-fsanitize-memory-track-origins

LDFLAGS+=-fsanitize=memory
#LDFLAGS+=-fsanitize-memory-track-origins

# MemorySanitizer does not support static linking
LDFLAGS_EXE:=$(filter-out -static -static-pie,$(LDFLAGS_EXE)) -pie
