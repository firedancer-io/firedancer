ifneq (,$(wildcard opt/lib/libssl.a))
OPENSSL_LIBS=opt/lib/libssl.a opt/lib/libcrypto.a

FD_HAS_OPENSSL:=1
CPPFLAGS+=-DFD_HAS_OPENSSL=1

CPPFLAGS+=-DOPENSSL_API_COMPAT=30000 -DOPENSSL_NO_DEPRECATED
else
$(warning "openssl not installed, skipping")
endif
