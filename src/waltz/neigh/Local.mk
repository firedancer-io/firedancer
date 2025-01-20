$(call add-hdrs,fd_neigh4_map.h fd_neigh4_map_defines.h)
$(call add-objs,fd_neigh4_map,fd_waltz)
ifdef FD_HAS_LINUX
ifdef FD_HAS_SSE
$(call add-hdrs,fd_neigh4_netlink.h)
$(call add-objs,fd_neigh4_netlink,fd_waltz)
$(call make-unit-test,test_neigh4_netlink,test_neigh4_netlink,fd_waltz fd_util)
endif
endif
