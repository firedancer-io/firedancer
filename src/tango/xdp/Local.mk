$(call add-hdrs,fd_xdp_redirect_prog.h)

ifdef FD_HAS_HOSTED
ifdef FD_HAS_LIBBPF
$(call make-lib,fd_xdp)
$(call add-hdrs,fd_xsk.h)
$(call add-objs,fd_xsk,fd_xdp)
endif
endif

