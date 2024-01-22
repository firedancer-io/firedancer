FD_HAS_LIBFF:=1
CFLAGS+=-DFD_HAS_LIBFF=1
LDFLAGS+=-Wl,--push-state,-Bstatic -lff -Wl,--pop-state -lgmp

$(info Using FD_HAS_LIBFF=1)
