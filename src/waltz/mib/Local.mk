$(call add-hdrs,fd_seqlock.h)
$(call add-hdrs,fd_netdev_tbl.h)
$(call add-objs,fd_netdev_tbl,fd_waltz)
ifdef FD_HAS_LINUX
$(call add-hdrs,fd_netdev_netlink.h)
$(call add-objs,fd_netdev_netlink,fd_waltz)
$(call make-unit-test,test_netdev_netlink,test_netdev_netlink,fd_waltz fd_util)
$(call make-unit-test,test_netdev_tbl,test_netdev_tbl,fd_waltz fd_util)
$(call run-unit-test,test_netdev_tbl)
endif
