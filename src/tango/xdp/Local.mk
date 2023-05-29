$(call add-hdrs,fd_xdp.h fd_xsk.h fd_xsk_aio.h fd_xdp_redirect_user.h)

ifdef FD_HAS_HOSTED
$(call add-hdrs,fd_xdp_redirect_prog.h)
$(call add-objs,fd_xsk fd_xsk_aio fd_xdp_redirect_user,fd_tango)

$(call make-bin,fd_xdp_ctl,fd_xdp_ctl,fd_tango fd_ballet fd_util)

$(call make-unit-test,test_xsk,test_xsk,fd_tango fd_ballet fd_util)
$(call run-unit-test,test_xsk)

$(call make-unit-test,test_xdp_ebpf,test_xdp_ebpf,fd_ballet fd_tango fd_util)
$(call run-unit-test,test_xdp_ebpf)

$(call make-unit-test,test_xdp_echo_aio,test_xdp_echo_aio,fd_tango fd_ballet fd_util)
$(call add-test-scripts,test_xdp_ctl test_xdp_init test_xdp_full test_xdp_fini)
endif # FD_HAS_HOSTED

