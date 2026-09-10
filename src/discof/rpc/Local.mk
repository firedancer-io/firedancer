$(call add-objs,fd_rpc_tile,fd_discof)
ifdef FD_HAS_HOSTED
$(call make-unit-test,test_rpc_tile,test_rpc_tile,fd_discof fd_disco fd_flamenco fd_waltz fd_tango fd_ballet fd_util)
$(call make-fuzz-test,fuzz_rpc,fuzz_rpc,fd_discof fd_disco fd_tango fd_flamenco fd_waltz fd_ballet fd_util)
$(call make-fuzz-test,fuzz_rpc_tarball,fuzz_rpc_tarball,fd_discof fd_disco fd_tango fd_flamenco fd_waltz fd_ballet fd_util)
endif
