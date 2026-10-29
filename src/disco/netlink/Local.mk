ifdef FD_HAS_LINUX
$(call add-hdrs,fd_netlink_tile.h)
$(call add-objs,fd_netlink_tile,fd_disco)
$(call make-proof,proof_netlink_route_sync,fd_netlink_tile_proofs.c)
endif
