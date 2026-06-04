ifdef FD_HAS_INT128
$(call add-objs,fd_genesi_tile fd_genesis_client,fd_discof)
ifdef FD_HAS_HOSTED
$(call make-fuzz-test,fuzz_genesis_client,fuzz_genesis_client,fd_discof fd_waltz fd_ballet fd_util)
endif
endif
