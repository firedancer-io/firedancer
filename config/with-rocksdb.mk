ifdef FD_HAS_ZSTD

ROCKSDB = /home/jsiegel/repos/rocksdb

ifeq (,$wildcard $(ROCKSDB)/librocksdb.a)
ROCKSDB = /usr/local
endif

ifneq (,$wildcard $(ROCKSDB)/librocksdb.a)
CFLAGS += -I$(ROCKSDB)/include -DFD_HAS_ROCKSDB=1
LDFLAGS += -lstdc++ $(ROCKSDB)/librocksdb.a -lpthread -lbz2 -lz -ldl -lm
FD_HAS_ROCKSDB:=1
endif

endif
