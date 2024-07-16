BUILDDIR:=macos/clang/m1

include config/base.mk
include config/extra/with-clang.mk
include config/extra/with-debug.mk
include config/extra/with-optimization.mk

# brew install llvm rocksdb zstd lz4

# CC:=/opt/homebrew/opt/llvm/bin/clang
# CXX:=/opt/homebrew/opt/llvm/bin/clang++
# LD:=/opt/homebrew/opt/llvm/bin/clang++

CPPFLAGS+=-DFD_HAS_INT128=1 -DFD_HAS_DOUBLE=1 -DFD_HAS_ALLOCA=1

# Remove this when we support FD_HAS_HOSTED for macOS
CPPFLAGS+=-DFD_ENV_STYLE=0 -DFD_IO_STYLE=0 -DFD_LOG_STYLE=0

# Remove this when we support FD_HAS_THREADS for macOS
CPPFLAGS+=-DFD_HAS_ATOMIC=1

CPPFLAGS+=-mcpu=apple-m1  # Requires AppleClang 14

FD_HAS_INT128:=1
FD_HAS_DOUBLE:=1
FD_HAS_ALLOCA:=1
FD_HAS_ATOMIC:=1

CPPFLAGS+=-isystem /opt/homebrew/include
LDFLAGS+=-L/opt/homebrew/lib

ifneq ($(wildcard /opt/homebrew/lib/librocksdb.dylib),)
FD_HAS_ROCKSDB:=1
CFLAGS+=-DFD_HAS_ROCKSDB=1 -DROCKSDB_LITE=1
ROCKSDB_LIBS:=-lrocksdb
FD_HAS_ROCKSDB:=1
endif

ifneq ($(wildcard /opt/homebrew/lib/libzstd.a),)
FD_HAS_ZSTD:=1
CFLAGS+=-DFD_HAS_ZSTD=1
LDFLAGS+=/opt/homebrew/lib/libzstd.a
endif

ifneq ($(wildcard /opt/homebrew/lib/liblz4.a),)
FD_HAS_LZ4:=1
CFLAGS+=-DFD_HAS_LZ4=1
LDFLAGS+=/opt/homebrew/lib/liblz4.a
endif

ifneq ($(wildcard /opt/homebrew/lib/libssl.dylib),)
OPENSSL_LIBS=-lssl
FD_HAS_OPENSSL:=1
CPPFLAGS+=-DFD_HAS_OPENSSL=1
CPPFLAGS+=-DOPENSSL_API_COMPAT=30000 -DOPENSSL_NO_DEPRECATED
endif
