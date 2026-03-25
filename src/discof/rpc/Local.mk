ifdef FD_HAS_ALLOCA
ifdef FD_HAS_LZ4
$(call add-objs,fd_rpc_tile,fd_discof)
$(call make-unit-test,test_rpc_tile,test_rpc_tile,fd_discof firedancer_version fd_disco fd_flamenco fd_waltz fd_vinyl fd_funk fd_tango fd_ballet fd_util)

ifdef FD_HAS_HOSTED
$(call make-fuzz-test,fuzz_rpc,fuzz_rpc,fd_discof firedancer_version fd_disco fd_tango fd_flamenco fd_vinyl fd_funk fd_waltz fd_ballet fd_util)

ifdef FD_HAS_BZIP2
$(call make-fuzz-test,fuzz_rpc_tarball,fuzz_rpc_tarball,fd_discof firedancer_version fd_disco fd_tango fd_flamenco fd_vinyl fd_funk fd_waltz fd_ballet fd_util)
endif
endif
endif
endif
