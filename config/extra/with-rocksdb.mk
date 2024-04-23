ifneq (,$(wildcard opt/lib/librocksdb.a))
ifneq (,$(wildcard opt/lib/libsnappy.a))
FD_HAS_ROCKSDB:=1
CFLAGS+=-DFD_HAS_ROCKSDB=1 -DROCKSDB_LITE=1
LDFLAGS+=-lz
ROCKSDB_LIBS:=opt/lib/librocksdb.a opt/lib/libsnappy.a
else
$(warning "snappy not installed, skipping rocksdb")
endif
else
$(warning "rocksdb not installed, skipping")
endif
