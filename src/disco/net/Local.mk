ifdef FD_HAS_ALLOCA
$(call add-hdrs,fd_net_tile.h)
$(call add-objs,fd_net_tile_topo,fd_disco)
endif
ifdef FD_HAS_LINUX
$(call add-objs,fd_linux_bond,fd_disco)
endif
$(call make-unit-test,test_net_checks,test_net_checks,fd_util)
$(call run-unit-test,test_net_checks)
ifdef FD_HAS_HOSTED
$(call make-fuzz-test,fuzz_net_checks,fuzz_net_checks,fd_util)
endif
