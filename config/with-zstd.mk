ZSTD = /usr/local

ifneq (,$wildcard $(ZSTD)/include/zstd.h)
CFLAGS += -I$(ZSTD)/include
LDFLAGS += -L$(ZSTD)/lib -lzstd
FD_HAS_ZSTD:=1
endif

