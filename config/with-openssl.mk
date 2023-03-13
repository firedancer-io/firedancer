inc_libcrypto=$(shell pkg-config libcrypto --cflags | sed s/-I/-isystem/)
inc_libssl=$(shell pkg-config libssl --cflags | sed s/-I/-isystem/)

libs_libcrypto=$(shell pkg-config libcrypto --libs)
libs_libssl=$(shell pkg-config libssl --libs)

CPPFLAGS+=$(inc_libcrypto) $(inc_libssl)
LDFLAGS+=$(libs_libcrypto) $(libs_libssl)

CPPFLAGS+=-DOPENSSL_API_COMPAT=0x10100000L -DOPENSSL_SUPPRESS_DEPRECATED
