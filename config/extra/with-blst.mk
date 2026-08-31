# Vendored in-tree (src/third_party/blst).  Kept as a separate
# trailing archive rather than folded into libfd_ballet.a: fdctl
# links agave_validator (which statically bundles its own blst crate
# copy) together with fd_ballet, and a trailing archive preserves the
# agave-copy-wins member selection the opt/ path had.
FD_HAS_BLST:=1
CFLAGS+=-DFD_HAS_BLST=1
BLST_LIBS=$(OBJDIR)/lib/libfd_blst.a
VENDOR_LINK_LIBS+=fd_blst
