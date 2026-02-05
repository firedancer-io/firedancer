$(call add-hdrs,fd_zksdk.h)
$(call add-objs,fd_zksdk,fd_ballet)
$(call make-unit-test,test_zksdk,test_zksdk,fd_ballet fd_util)
$(call run-unit-test,test_zksdk)
