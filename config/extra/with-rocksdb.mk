ifneq (,$(wildcard $(OPT)/lib/librocksdb.a))
ifneq (,$(wildcard $(OPT)/lib/libsnappy.a))
ifneq (,$(wildcard $(OPT)/lib/libzstd.a))
FD_HAS_ROCKSDB:=1
CFLAGS+=-DFD_HAS_ROCKSDB=1 -DROCKSDB_LITE=1
ROCKSDB_LIBS:=$(OPT)/lib/librocksdb.a $(OPT)/lib/libsnappy.a

# RocksDB enables io_uring support opportunistically; only link liburing when
# the static archive actually references its symbols (e.g. Arch Linux builds).
ifneq (,$(shell nm -A $(OPT)/lib/librocksdb.a 2>/dev/null | grep -F io_uring_queue_init))
ROCKSDB_LIBS+=-luring
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
