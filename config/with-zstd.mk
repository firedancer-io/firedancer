ZSTD = /usr/local

ifneq (,$wildcard $(ZSTD)/include/zstd.h)
CFLAGS += -I$(ZSTD)/include  -DFD_HAS_ZSTD=1
LDFLAGS += -L$(ZSTD)/lib -lzstd
FD_HAS_ZSTD:=1
endif

