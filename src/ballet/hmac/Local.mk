$(call add-hdrs,fd_hmac.h)
$(call add-objs,fd_hmac,fd_ballet)
$(call make-unit-test,test_hmac,test_hmac,fd_ballet fd_util)
$(call run-unit=test,test_hmac)
