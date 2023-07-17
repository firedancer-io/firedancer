ifneq ($(ROCKSDB),)

ifneq (,$(wildcard $(ROCKSDB)/librocksdb.a))
CFLAGS += -I$(ROCKSDB)/include -DFD_HAS_ROCKSDB=1
LDFLAGS += -lstdc++ $(ROCKSDB)/librocksdb.a -lpthread -lbz2 -lz -ldl -lm
FD_HAS_ROCKSDB:=1
endif

else

CFLAGS += -DFD_HAS_ROCKSDB=1
LDFLAGS += -lrocksdb -lbz2 -lz
FD_HAS_ROCKSDB:=1

endif
