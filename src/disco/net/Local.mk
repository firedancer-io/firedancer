ifdef FD_HAS_ALLOCA
$(call add-hdrs,fd_net_tile.h)
$(call add-objs,fd_net_tile_topo,fd_disco)
endif
ifdef FD_HAS_LINUX
$(call add-objs,fd_linux_bond,fd_disco)
endif
