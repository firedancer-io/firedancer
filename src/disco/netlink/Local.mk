ifdef FD_HAS_LINUX
ifdef FD_HAS_SSE
$(call add-hdrs,fd_netlink_tile.h)
$(call add-objs,fd_netlink_tile,fd_disco)
endif
endif
