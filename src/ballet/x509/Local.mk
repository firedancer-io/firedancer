# X.509 cert parser
$(call add-hdrs,fd_x509_cert_parser.h fd_x509_common.h fd_x509_config.h fd_x509_utils.h)
$(call add-objs,fd_x509_cert_parser fd_x509_common,fd_ballet)

# X.509 mock cert generator
$(call add-hdrs,fd_x509_mock.h)
$(call add-objs,fd_x509_mock,fd_ballet)
$(call make-unit-test,test_x509_mock,test_x509_mock,fd_ballet fd_util)
$(call run-unit-test,test_x509_mock)
