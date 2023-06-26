$(call add-hdrs,fd_scratch.h)
$(call add-objs,fd_scratch,fd_util)
$(call make-unit-test,test_scratch,test_scratch,fd_util)
$(call run-unit-test,test_scratch,)

