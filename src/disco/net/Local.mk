ifdef FD_HAS_HOSTED
$(call add-hdrs,fd_net_tile.h)
$(call add-objs,fd_net_tile_topo,fd_disco)
endif
ifdef FD_HAS_LINUX
$(call make-unit-test,test_net_ip4_frag,test_net_ip4_frag,fd_disco fd_ballet fd_tango fd_waltz fd_util)
$(call run-unit-test,test_net_ip4_frag)
$(call make-unit-test,test_net_rx,test_net_rx,fd_disco fd_ballet fd_tango fd_waltz fd_util)
$(call run-unit-test,test_net_rx)
$(call add-objs,fd_linux_bond,fd_disco)
$(call add-objs,fd_net_tile_fib4,fd_disco)
endif
