# Vendored in-tree (src/third_party/zstd), standalone trailing
# archive (some targets, e.g. test_libc_zstd, link without fd_ballet
# and resolve ZSTD_* from LDFLAGS).
FD_HAS_ZSTD:=1
CFLAGS+=-DFD_HAS_ZSTD=1
CPPFLAGS:=-isystem src/third_party/zstd/lib $(CPPFLAGS)
VENDOR_LINK_LIBS+=fd_zstd
