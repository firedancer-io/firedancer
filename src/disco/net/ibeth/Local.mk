ifdef FD_HAS_IBVERBS
$(call add-objs,fd_ibeth_tile,fd_disco)
$(call make-unit-test,test_ibeth_tile,test_ibeth_tile,fd_disco fd_waltz fd_tango fd_util,$(IBVERBS_LIBS))
endif
