$(call add-hdrs,fd_genesis_cluster.h)
$(call add-objs,fd_genesis_cluster,fd_disco)

ifdef FD_HAS_HOSTED
$(call add-objs,fd_genesi_tile fd_genesis_client,fd_disco)
$(call make-fuzz-test,fuzz_genesis_client,fuzz_genesis_client,fd_disco fd_waltz fd_ballet fd_util)
endif
