$(call add-hdrs,fd_xsk.h fd_xdp_redirect_user.h)

ifdef FD_HAS_HOSTED
ifdef FD_HAS_LINUX
$(call add-objs,fd_xsk fd_xdp1 fd_xdp_redirect_user,fd_waltz)

$(call make-unit-test,test_xsk,test_xsk,fd_waltz fd_util)
$(call run-unit-test,test_xsk)

$(call make-unit-test,test_xdp_ebpf,test_xdp_ebpf,fd_waltz fd_util)
$(call run-unit-test,test_xdp_ebpf)
endif # FD_HAS_LINUX
endif # FD_HAS_HOSTED

