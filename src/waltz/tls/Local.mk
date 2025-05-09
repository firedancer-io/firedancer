$(call make-lib,fd_tls)
$(call add-hdrs,fd_tls.h fd_tls_proto.h fd_tls_asn1.h fd_tls_estate.h)
$(call add-objs,fd_tls fd_tls_proto fd_tls_asn1,fd_tls)

$(call add-hdrs,test_tls_helper.h)
$(call make-unit-test,test_tls,test_tls,fd_tls fd_ballet fd_util)
$(call run-unit-test,test_tls)
ifdef FD_HAS_HOSTED
$(call make-fuzz-test,fuzz_tls,fuzz_tls,fd_tls fd_ballet fd_util)
$(call make-fuzz-test,fuzz_tls_msg_parser,fuzz_tls_msg_parser,fd_tls fd_ballet fd_util)
endif

# Uncomment this to test against quictls.  Upstream OpenSSL does not
# support this test.
#ifdef FD_HAS_OPENSSL
#$(call make-unit-test,test_tls_openssl,test_tls_openssl,fd_quic fd_tls fd_ballet fd_util,-lssl -lcrypto)
#$(call run-unit-test,test_tls_openssl)
#endif
