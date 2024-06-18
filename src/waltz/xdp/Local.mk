$(call add-hdrs,fd_xdp.h fd_xsk.h fd_xsk_aio.h fd_xdp_redirect_user.h)

ifdef FD_HAS_HOSTED
$(call add-hdrs,fd_xdp_redirect_prog.h)
$(call add-objs,fd_xsk fd_xsk_aio fd_xdp_redirect_user,fd_waltz)

$(call make-unit-test,test_xsk,test_xsk,fd_waltz fd_util)
$(call run-unit-test,test_xsk)

$(call make-unit-test,test_xdp_ebpf,test_xdp_ebpf,fd_waltz fd_util)
$(call run-unit-test,test_xdp_ebpf)

$(call make-unit-test,test_xsk_aio_echo_rx,test_xsk_aio_echo_rx,fd_waltz fd_tango fd_util)
$(call add-test-scripts,test_xsk_aio_echo_tx)
endif # FD_HAS_HOSTED

