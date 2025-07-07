ifdef FD_HAS_SSE
ifdef FD_HAS_ALLOCA
$(call add-objs,fd_xdp_tile,fd_disco)
$(call make-unit-test,test_xdp_tile,test_xdp_tile,fd_disco fd_tango fd_waltz fd_util)
endif
endif
