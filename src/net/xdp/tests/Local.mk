$(call make-bin,test_recv,test_recv,fd_xdp fd_util)
$(call make-bin,test_send,test_send,fd_xdp fd_util)
$(call make-bin,test_echo,test_echo,fd_xdp fd_util)
$(call make-bin,test_echo_aio,test_echo_aio,fd_aio fd_xdp fd_util)

