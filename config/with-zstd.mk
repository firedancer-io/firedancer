ifeq ($(ZSTD),)
ZSTD = /usr/local
endif

ifneq (,$(wildcard $(ZSTD)/include/zstd.h))
CFLAGS += -I$(ZSTD)/include  -DFD_HAS_ZSTD=1
LDFLAGS += -L$(ZSTD)/lib -lzstd
FD_HAS_ZSTD:=1
else

# Use packaged libzstd if none manually installed
CFLAGS += -DFD_HAS_ZSTD=1
LDFLAGS += $(shell pkg-config --libs libzstd)
FD_HAS_ZSTD:=1

endif

