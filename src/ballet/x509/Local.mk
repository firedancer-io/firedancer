$(call add-hdrs,fd_x509_mock.h fd_der.h)
$(call add-objs,fd_x509_mock,fd_ballet)

$(call make-unit-test,test_der,test_der,fd_ballet fd_util)
$(call run-unit-test,test_der)

$(call make-unit-test,test_x509,test_x509,fd_ballet fd_util)
$(call run-unit-test,test_x509)
