$(call make-ebpf-bin,ebpf_xdp_flow)
$(call make-lib,fd_xdp)
$(call make-lib,fd_xdp_fs)
$(call make-bin,fd_quic_attach,fd_quic_attach fd_xdp_fs,fd_util)
$(call make-bin,fd_quic_detach,fd_quic_detach fd_xdp_fs,fd_util)
$(call make-bin,test_recv,test_recv fd_xdp_fs fd_xdp,fd_util)
$(call make-bin,test_send,test_send fd_xdp_fs fd_xdp,fd_util)

