# Vendored in-tree (src/third_party/lz4); objects live in
# libfd_util.a so fd_util-only targets resolve them.
FD_HAS_LZ4:=1
CFLAGS+=-DFD_HAS_LZ4=1
CPPFLAGS+=-isystem src/third_party/lz4/lib
