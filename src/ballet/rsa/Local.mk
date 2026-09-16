$(call add-hdrs,fd_rsa.h)
ifdef FD_HAS_INT128
$(call add-objs,fd_rsa,fd_ballet)
$(call make-unit-test,test_rsa,test_rsa,fd_ballet fd_util)
$(call run-unit-test,test_rsa)
endif # FD_HAS_INT128
