FD_HAS_LIBMICROHTTP:=1
CFLAGS+=-DFD_HAS_LIBMICROHTTP=1
LDFLAGS+=-Wl,--push-state,-Bstatic -lmicrohttpd -Wl,--pop-state
