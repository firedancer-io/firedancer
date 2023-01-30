$(call make-ebpf-bin,ebpf_xdp_flow)
$(call make-lib,fd_xdp)
$(call add-objs,fd_xdp,fd_xdp)

