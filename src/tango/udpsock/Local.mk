$(call add-hdrs,fd_udpsock.h)
$(call add-objs,fd_udpsock,fd_tango)
$(call make-unit-test,test_udpsock_echo,test_udpsock_echo,fd_tango fd_util)
