ifdef FD_HAS_SSE
ifdef FD_HAS_ALLOCA
$(call add-objs,fd_xdp_tile fd_xdp_tile_softirq fd_xdp_tile_poll,fd_disco)
endif
endif
