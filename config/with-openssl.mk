LDFLAGS+=-Wl,--push-state,-Bstatic $(shell pkg-config --libs libssl libcrypto) -Wl,--pop-state

FD_HAS_OPENSSL:=1
CPPFLAGS+=-DFD_HAS_OPENSSL=1

CPPFLAGS+=-DOPENSSL_API_COMPAT=0x10100000L -DOPENSSL_SUPPRESS_DEPRECATED
