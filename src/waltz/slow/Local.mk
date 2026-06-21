$(call add-hdrs,fd_wheel.h)
$(call add-objs,fd_wheel,fd_waltz)
$(call make-unit-test,test_wheel,test_wheel,fd_waltz fd_util)
$(call run-unit-test,test_wheel)
