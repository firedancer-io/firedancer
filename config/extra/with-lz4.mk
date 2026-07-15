# Vendored in-tree (src/third_party/lz4), standalone trailing archive:
# resolves fd_util's LZ4 refs (checkpt/wksp/vinyl) and, on single-pass
# linkers, librocksdb.a's, which appears after -lfd_util on link lines.
# $(BASEDIR)/$(BUILDDIR) spelled out: OBJDIR is not defined until
# everything.mk and LDFLAGS is simply-expanded.
FD_HAS_LZ4:=1
CFLAGS+=-DFD_HAS_LZ4=1
CPPFLAGS+=-isystem src/third_party/lz4/lib
LDFLAGS+=$(BASEDIR)/$(BUILDDIR)/lib/libfd_lz4.a
