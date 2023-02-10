
ROCKSDB = /home/jsiegel/repos/rocksdb

ifneq (,$wildcard $(ROCKSDB)/librocksdb.a)
CFLAGS += -I$(ROCKSDB)/include
LDFLAGS += -lstdc++ $(ROCKSDB)/librocksdb.a -L /usr/local/lib -lzstd -lpthread -lbz2 -lz -ldl  -lm
FD_HAS_ROCKSDB:=1
endif
