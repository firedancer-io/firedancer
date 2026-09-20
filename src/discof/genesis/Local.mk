ifdef FD_HAS_HOSTED
$(call add-objs,fd_genesi_tile fd_genesis_client,fd_discof)
$(call make-unit-test,test_genesis_client,test_genesis_client,fd_waltz fd_ballet fd_util)
$(call run-unit-test,test_genesis_client)
$(call make-fuzz-test,fuzz_genesis_client,fuzz_genesis_client,fd_discof fd_waltz fd_ballet fd_util)
endif
