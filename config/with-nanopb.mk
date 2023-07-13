LDFLAGS+=-Wl,--push-state,-Bstatic $(shell pkg-config --libs nanopb) -Wl,--pop-state

FD_HAS_NANOPB:=1
CPPFLAGS+=-DFD_HAS_NANOPB=1
