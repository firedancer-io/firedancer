# Vendored in-tree (src/third_party/lz4), standalone trailing archive
# resolving fd_util's LZ4 refs (checkpt/wksp/vinyl).
FD_HAS_LZ4:=1
CFLAGS+=-DFD_HAS_LZ4=1
CPPFLAGS:=-isystem src/third_party/lz4/lib $(CPPFLAGS)
VENDOR_LINK_LIBS+=fd_lz4
