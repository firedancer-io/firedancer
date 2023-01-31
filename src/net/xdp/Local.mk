$(call make-lib,fd_xdp)
$(call add-objs,fd_xdp fd_xdp_fs fd_xdp_aio,fd_xdp)
$(call make-bin,fd_quic_attach,fd_quic_attach,fd_xdp fd_util)
$(call make-bin,fd_quic_detach,fd_quic_detach,fd_xdp fd_util)
$(call make-bin,test_recv,test_recv,fd_xdp fd_util)
$(call make-bin,test_send,test_send,fd_xdp fd_util)
$(call make-bin,test_echo,test_echo,fd_xdp fd_util)

