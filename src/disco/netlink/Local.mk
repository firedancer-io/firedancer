ifdef FD_HAS_LINUX
$(call add-hdrs,fd_netlink_tile.h)
$(call add-objs,fd_netlink_tile,fd_disco)
endif
ifdef FD_HAS_LINUX
$(call make-unit-test,test_netlink_probe,test_netlink_probe,fd_disco fd_waltz fd_tango fd_ballet fd_util)
$(call run-unit-test,test_netlink_probe)
endif
