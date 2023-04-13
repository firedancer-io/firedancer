ifdef FD_HAS_HOSTED

$(call make-lib,fd_xdp)
$(call add-hdrs,fd_xdp.h fd_xsk.h fd_xsk_aio.h fd_xdp_redirect_prog.h fd_xdp_redirect_user.h)
$(call add-objs,fd_xsk fd_xsk_aio,fd_xdp)

ifdef FD_HAS_LIBBPF
$(call add-objs,fd_xdp_redirect_user,fd_xdp)
$(call make-unit-test,test_xsk,test_xsk,fd_xdp fd_util)
$(call run-unit-test,test_xsk)
endif # FD_HAS_LIBBPF

endif # FD_HAS_HOSTED

