$(call add-hdrs,fd_xdp.h fd_xsk.h fd_xsk_aio.h fd_xdp_redirect_user.h)

ifdef FD_HAS_HOSTED
ifdef FD_HAS_LINUX
$(call add-hdrs,fd_xdp_redirect_prog.h)
$(call add-objs,fd_xsk fd_xdp1 fd_xsk_aio fd_xdp_redirect_user,fd_waltz)

$(call make-unit-test,test_xsk,test_xsk,fd_waltz fd_util)
$(call run-unit-test,test_xsk)

$(call make-unit-test,test_xdp_ebpf,test_xdp_ebpf,fd_waltz fd_util)
$(call run-unit-test,test_xdp_ebpf)

$(call make-unit-test,test_xsk_dump,test_xsk_dump,fd_waltz fd_tango fd_util)
$(call make-unit-test,test_xsk_rxdrop,test_xsk_rxdrop,fd_waltz fd_tango fd_util)
endif # FD_HAS_LINUX
endif # FD_HAS_HOSTED

