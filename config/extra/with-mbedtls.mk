ifneq (,$(wildcard $(OPT)/lib/libmbedtls.a))
MBEDTLS_LIBS=$(OPT)/lib/libmbedtls.a $(OPT)/lib/libmbedcrypto.a $(OPT)/lib/libmbedx509.a

FD_HAS_MBEDTLS:=1
CPPFLAGS+=-DFD_HAS_MBEDTLS=1
else
$(info "MbedTLS not installed, skipping")
endif
