
ROCKSDB = /home/jsiegel/repos/rocksdb

ifeq (,$wildcard $(ROCKSDB)/librocksdb.a)
ROCKSDB = /usr/local
endif

ifneq (,$wildcard $(ROCKSDB)/librocksdb.a)
CFLAGS += -I$(ROCKSDB)/include
LDFLAGS += -lstdc++ $(ROCKSDB)/librocksdb.a -lpthread -lbz2 -lz -ldl -lm
FD_HAS_ROCKSDB:=1
endif
