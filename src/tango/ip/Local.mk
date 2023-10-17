$(call add-hdrs,fd_ip.h)
$(call add-objs,fd_ip fd_netlink,fd_tango)
$(call make-unit-test,test_netlink,test_netlink,fd_tango fd_util)
$(call make-unit-test,test_ip,test_ip,fd_tango fd_util)
$(call make-unit-test,test_routing,test_routing,fd_tango fd_util)
$(call make-unit-test,test_arp,test_arp,fd_tango fd_util)

$(call run-unit-test,test_netlink)
$(call run-unit-test,test_routing)
