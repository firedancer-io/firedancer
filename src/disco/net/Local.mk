ifdef FD_HAS_HOSTED
$(call add-hdrs,fd_net_tile.h)
$(call add-objs,fd_net_tile_topo,fd_disco)
endif
ifdef FD_HAS_LINUX
$(call add-objs,fd_linux_bond,fd_disco)
$(call add-objs,fd_net_tile_fib4,fd_disco)
$(call add-objs,fd_net_sock,fd_disco)
$(call make-unit-test,test_net_sock,test_net_sock,fd_disco fd_tango fd_util)
$(call run-unit-test,test_net_sock)
endif
