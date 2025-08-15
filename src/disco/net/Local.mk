ifdef FD_HAS_ALLOCA
$(call add-hdrs,fd_net_tile.h)
$(call add-objs,fd_net_tile_topo,fd_disco)
endif
$(call add-hdrs,fd_find_16x16.h)
$(call make-unit-test,test_find_16x16,test_find_16x16,fd_util)
$(call run-unit-test,test_find_16x16)
