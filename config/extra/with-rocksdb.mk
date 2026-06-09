ifneq (,$(wildcard $(OPT)/lib/librocksdb.a))
ifneq (,$(wildcard $(OPT)/lib/libsnappy.a))
ifneq (,$(wildcard $(OPT)/lib/libzstd.a))
FD_HAS_ROCKSDB:=1
FD_HAS_CXX:=1
CFLAGS+=-DFD_HAS_ROCKSDB=1 -DROCKSDB_LITE=1
ROCKSDB_LIBS:=$(OPT)/lib/librocksdb.a $(OPT)/lib/libsnappy.a
ifndef LIBCXX
ROCKSDB_LIBS+=-lstdc++
endif

else
$(warning "zstd not installed, skipping rocksdb")
endif
else
$(warning "snappy not installed, skipping rocksdb")
endif
else
$(warning "rocksdb not installed, skipping")
endif
