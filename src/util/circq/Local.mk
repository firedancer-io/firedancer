ifdef FD_HAS_HOSTED
$(call add-hdrs,fd_circq.h)
$(call add-objs,fd_circq,fd_util)
$(call make-unit-test,test_circq,test_circq,fd_util)
$(call run-unit-test,test_circq)
endif
