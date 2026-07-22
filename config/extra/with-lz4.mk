FD_HAS_LZ4:=1
CFLAGS+=-DFD_HAS_LZ4=1
CPPFLAGS+=-isystem src/third_party/lz4/lib
LDFLAGS+=$(BASEDIR)/$(BUILDDIR)/lib/libfd_lz4.a
