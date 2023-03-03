$(call add-hdrs,fd_cstr.h)
$(call add-objs,fd_cstr,fd_util)
$(call make-unit-test,test_cstr,test_cstr,fd_util)
$(call run-unit-test,test_cstr,)

