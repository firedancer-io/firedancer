ifdef FD_HAS_ZSTD

ifneq ($(ROCKSDB),)

ifneq (,$wildcard $(ROCKSDB)/librocksdb.a)
CFLAGS += -I$(ROCKSDB)/include -DFD_HAS_ROCKSDB=1
LDFLAGS += -lstdc++ $(ROCKSDB)/librocksdb.a -lpthread -lbz2 -lz -ldl -lm
FD_HAS_ROCKSDB:=1
endif

else

CFLAGS  += $(shell pkg-config --cflags rockdb)
LDFLAGS += $(shell pkg-config --libs rockdb)

endif

endif
