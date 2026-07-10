ifneq (,$(wildcard $(OPT)/lib/librocksdb.a))
ifneq (,$(wildcard $(OPT)/lib/libsnappy.a))
# zstd is vendored (with-zstd.mk parses first); rocksdb's ZDICT_*/
# LZ4_* refs resolve from the trailing libfd_zstd.a / libfd_lz4.a.
ifdef FD_HAS_ZSTD
FD_HAS_ROCKSDB:=1
CFLAGS+=-DFD_HAS_ROCKSDB=1 -DROCKSDB_LITE=1
ROCKSDB_LIBS:=$(OPT)/lib/librocksdb.a $(OPT)/lib/libsnappy.a -lstdc++
endif
endif
endif
