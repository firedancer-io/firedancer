ifdef FD_HAS_DOUBLE
$(call add-hdrs,fd_clock.h)
$(call add-objs,fd_clock,fd_util)
$(call make-unit-test,test_clock,test_clock,fd_util)
$(call run-unit-test,test_clock)
endif
