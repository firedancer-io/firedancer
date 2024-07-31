BUILDDIR:=freebsd/clang/noarch128

include config/base.mk
include config/extra/with-security.mk
include config/extra/with-clang.mk
include config/extra/with-debug.mk
include config/extra/with-brutality.mk
include config/extra/with-optimization.mk
include config/extra/with-threads.mk

CPPFLAGS+=-DFD_HAS_INT128=1 -DFD_HAS_DOUBLE=1 -DFD_HAS_ALLOCA=1

FD_HAS_INT128:=1
FD_HAS_DOUBLE:=1
FD_HAS_ALLOCA:=1

CPPFLAGS+=-isystem /usr/local/include
LDFLAGS+=-L/usr/local/lib

# pkg install secp256k1 rocksdb liblz4 zstd openssl

FD_HAS_SECP256K1:=1
CFLAGS+=-DFD_HAS_SECP256K1=1
SECP256K1_LIBS:=-lsecp256k1

FD_HAS_ROCKSDB:=1
CFLAGS+=-DFD_HAS_ROCKSDB=1 -DROCKSDB_LITE=1
ROCKSDB_LIBS:=-lrocksdb -lz -lsnappy

FD_HAS_ZSTD:=1
CFLAGS+=-DFD_HAS_ZSTD
LDFLAGS+=/usr/local/lib/libzstd.a

FD_HAS_OPENSSL:=1
CPPFLAGS+=-DFD_HAS_OPENSSL=1 -DOPENSSL_API_COMPAT=30000 -DOPENSSL_NO_DEPRECATED
OPENSSL_LIBS=opt/lib/libssl.a opt/lib/libcrypto.a
