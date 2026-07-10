# Vendored in-tree (src/third_party/zstd), standalone trailing
# archive (some targets, e.g. test_libc_zstd, link without fd_ballet
# and resolve ZSTD_* from LDFLAGS).
# $(BASEDIR)/$(BUILDDIR) spelled out: OBJDIR is not defined until
# everything.mk and LDFLAGS is simply-expanded.
FD_HAS_ZSTD:=1
CFLAGS+=-DFD_HAS_ZSTD=1
CPPFLAGS+=-isystem src/third_party/zstd/lib
LDFLAGS+=$(BASEDIR)/$(BUILDDIR)/lib/libfd_zstd.a
