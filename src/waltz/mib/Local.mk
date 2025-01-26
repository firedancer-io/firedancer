$(call add-hdrs,fd_dbl_buf.h)
$(call add-objs,fd_dbl_buf,fd_waltz)
$(call add-hdrs,fd_netdev_tbl.h)
$(call add-objs,fd_netdev_tbl,fd_waltz)
ifdef FD_HAS_LINUX
$(call add-hdrs,fd_netdev_netlink.h)
$(call add-objs,fd_netdev_netlink,fd_waltz)
$(call make-unit-test,test_netdev_netlink,test_netdev_netlink,fd_waltz fd_util)
endif
