$(call add-hdrs,fd_neigh4_map.h fd_neigh4_map_defines.h)
$(call add-objs,fd_neigh4_map,fd_waltz)
ifdef FD_HAS_LINUX
$(call add-hdrs,fd_neigh4_netlink.h fd_neigh4_probe.h)
$(call add-objs,fd_neigh4_netlink fd_neigh4_probe,fd_waltz)
$(call make-unit-test,test_neigh4_netlink,test_neigh4_netlink,fd_waltz fd_util)
endif
