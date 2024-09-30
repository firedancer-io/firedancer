ifneq (,$(wildcard $(OPT)/lib/librocksdb.a))
ifneq (,$(wildcard $(OPT)/lib/libsnappy.a))
FD_HAS_ROCKSDB:=1
CFLAGS+=-DFD_HAS_ROCKSDB=1 -DROCKSDB_LITE=1
ROCKSDB_LIBS:=$(OPT)/lib/librocksdb.a $(OPT)/lib/libsnappy.a
else
$(warning "snappy not installed, skipping rocksdb")
endif
else
$(warning "rocksdb not installed, skipping")
endif
