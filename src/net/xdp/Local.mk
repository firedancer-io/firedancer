$(call make-ebpf-bin,ebpf_xdp_flow)
$(call make-lib,fd_xdp)
$(call add-objs,fd_xdp,fd_xdp)
$(call add-objs,fd_xdp fd_xdp_fs fd_xdp_aio,fd_xdp)

