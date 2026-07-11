# Vendored in-tree (src/third_party/blst).  Kept as a separate
# trailing archive rather than folded into libfd_ballet.a: fdctl
# links agave_validator (which statically bundles its own blst crate
# copy) together with fd_ballet, and a trailing archive preserves the
# agave-copy-wins member selection the opt/ path had.
# $(BASEDIR)/$(BUILDDIR) spelled out: OBJDIR is not defined until
# everything.mk and LDFLAGS is simply-expanded.
FD_HAS_BLST:=1
CFLAGS+=-DFD_HAS_BLST=1
BLST_LIBS:=$(BASEDIR)/$(BUILDDIR)/lib/libfd_blst.a
LDFLAGS+=$(BLST_LIBS)
