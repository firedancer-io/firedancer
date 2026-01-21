ifdef FD_HAS_ALLOCA
$(call add-objs,fd_rpc_tile,fd_discof)
$(call make-unit-test,test_rpc_tile,test_rpc_tile,fd_discof firedancer_version fd_disco fd_flamenco fd_waltz fd_vinyl fd_funk fd_tango fd_ballet fd_util)
endif
