FD_HAS_ROCKSDB:=1
CFLAGS+=-DFD_HAS_ROCKSDB=1 -DROCKSDB_LITE=1
LDFLAGS+=-lz
ROCKSDB_LIBS:=opt/lib/librocksdb.a opt/lib/libsnappy.a
