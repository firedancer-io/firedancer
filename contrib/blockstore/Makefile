CC      ?= cc
CFLAGS  ?= -O2 -g
CPPFLAGS?=
LDFLAGS ?=
LDLIBS  += -lrocksdb

.PHONY: all clean

all: blockstore2shredcap blockstore_minify

blockstore2shredcap: LDLIBS += -lzstd
blockstore2shredcap: blockstore2shredcap.c
blockstore_minify: blockstore_minify.c

clean:
	rm -f blockstore2shredcap blockstore_minify
