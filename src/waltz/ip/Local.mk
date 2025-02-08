$(call add-hdrs,fd_fib4.h)
$(call add-objs,fd_fib4,fd_waltz)
ifdef FD_HAS_LINUX
$(call add-objs,fd_netlink1 fd_fib4_netlink,fd_waltz)
$(call make-unit-test,test_fib4_netlink,test_fib4_netlink,fd_waltz fd_util)
$(call run-unit-test,test_fib4_netlink)
endif
$(call make-unit-test,test_fib4,test_fib4,fd_waltz fd_util)
$(call run-unit-test,test_fib4)
