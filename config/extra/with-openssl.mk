ifneq (,$(wildcard $(OPT)/lib/libssl.a))
OPENSSL_LIBS=$(OPT)/lib/libssl.a $(OPT)/lib/libcrypto.a

FD_HAS_OPENSSL:=1
CPPFLAGS+=-DFD_HAS_OPENSSL=1

CPPFLAGS+=-DOPENSSL_API_COMPAT=30000 -DOPENSSL_NO_DEPRECATED
else
$(info "openssl not installed, skipping")
endif
