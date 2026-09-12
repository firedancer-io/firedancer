$(call add-hdrs,fd_der.h)
$(call make-unit-test,test_der,test_der,fd_ballet fd_util)
$(call run-unit-test,test_der)

$(call add-hdrs,fd_x509.h fd_x509_mock.h fd_x509_verify.h)
$(call add-objs,fd_x509 fd_x509_mock fd_x509_verify,fd_ballet)
$(call make-unit-test,test_x509,test_x509,fd_ballet fd_util)
$(call run-unit-test,test_x509)

ifdef FD_HAS_HOSTED
$(call add-hdrs,fd_x509_ca_store.h)
$(call add-objs,fd_x509_ca_store,fd_ballet)
$(call make-unit-test,test_x509_verify,test_x509_verify,fd_ballet fd_util)
$(call run-unit-test,test_x509_verify)
$(call make-fuzz-test,fuzz_x509_cert_parse,fuzz_x509_cert_parse,fd_ballet fd_util)
$(call make-fuzz-test,fuzz_x509_tls_cert_msg,fuzz_x509_tls_cert_msg,fd_ballet fd_util)
endif
