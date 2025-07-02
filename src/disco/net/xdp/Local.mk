ifdef FD_HAS_ALLOCA
$(call add-objs,fd_xdp_tile,fd_disco)
ifdef FD_ARCH_SUPPORTS_SANDBOX
$(call make-unit-test,test_xdp_tile,test_xdp_tile,fd_disco fd_tango fd_waltz fd_util)
$(call make-unit-test,test_xdp_tile1,test_xdp_tile1,fdctl_shared fdctl_platform fd_disco fd_flamenco fd_ballet fd_tango fd_waltz fd_reedsol fd_funk fd_util)
$(call run-unit-test,test_xdp_tile)
$(call run-unit-test,test_xdp_tile1)
endif
endif
