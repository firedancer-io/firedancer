LDFLAGS+=-Wl,--push-state,-Bstatic -lprotobuf-nanopb -Wl,--pop-state

FD_HAS_NANOPB:=1
CPPFLAGS+=-DFD_HAS_NANOPB=1
