$(call make-ebpf-bin,ebpf_xdp_flow)
$(call make-lib,fd_xdp)
$(call add-objs,fd_xdp fd_xdp_fs fd_xdp_aio,fd_xdp)
$(call make-bin,fd_quic_attach,fd_quic_attach,fd_xdp fd_util)
$(call make-bin,fd_quic_detach,fd_quic_detach,fd_xdp fd_util)

