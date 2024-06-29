$(call add-hdrs,fd_spad.h)
$(call add-objs,fd_spad,fd_util)
$(call make-unit-test,test_spad,test_spad,fd_util)
$(call run-unit-test,test_spad,)
