ifdef FD_HAS_HOSTED
$(call add-hdrs,fd_udpsock.h)
$(call add-objs,fd_udpsock,fd_waltz_test)
$(call make-unit-test,test_udpsock_echo,test_udpsock_echo,fd_waltz_test fd_waltz fd_util)
endif
