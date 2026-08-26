CC      ?= cc
CFLAGS  ?= -O2 -g
CPPFLAGS?=
LDFLAGS ?=
LDLIBS  += -lrocksdb

# Prefer a local RocksDB install over the system one when present.
ROCKSDB_PREFIX ?= /opt/rocksdb/rocksdb-11.1.1
ifneq ($(wildcard $(ROCKSDB_PREFIX)/include/rocksdb/c.h),)
CPPFLAGS += -I$(ROCKSDB_PREFIX)/include
LDFLAGS  += -L$(ROCKSDB_PREFIX)/lib -Wl,-rpath,$(ROCKSDB_PREFIX)/lib
endif

.PHONY: all clean

all: blockstore2shredcap blockstore_minify

blockstore2shredcap: LDLIBS += -lzstd
blockstore2shredcap: blockstore2shredcap.c
blockstore_minify: blockstore_minify.c

clean:
	rm -f blockstore2shredcap blockstore_minify
