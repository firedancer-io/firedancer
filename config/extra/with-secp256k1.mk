FD_HAS_SECP256K1:=1
CFLAGS+=-DFD_HAS_SECP256K1=1
LDFLAGS+=-Wl,--push-state,-Bstatic -lsecp256k1 -Wl,--pop-state
