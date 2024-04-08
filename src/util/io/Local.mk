$(call add-hdrs,fd_io.h)
$(call add-objs,fd_io,fd_util)
$(call make-unit-test,test_io,test_io,fd_util)
$(call run-unit-test,test_io,)
