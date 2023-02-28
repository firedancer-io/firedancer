$(call add-hdrs,fd_xdp_redirect_prog.h)
$(call make-ebpf-bin,fd_xdp_redirect_prog)

ifdef FD_HAS_HOSTED
ifdef FD_HAS_LIBBPF
$(call make-lib,fd_xdp)
$(call add-hdrs,fd_xdp.h fd_xsk.h fd_xsk_aio.h)
$(call add-objs,fd_xsk fd_xsk_aio,fd_xdp)
endif
endif

