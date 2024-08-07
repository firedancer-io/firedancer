ifdef FD_HAS_HOSTED
ifdef FD_HAS_LINUX
$(call add-hdrs,fd_ip.h)
$(call add-objs,fd_ip fd_netlink,fd_waltz)
$(call make-unit-test,test_netlink,test_netlink,fd_waltz fd_util)
$(call make-unit-test,test_ip_dump,test_ip_dump,fd_waltz fd_util)
$(call add-test-scripts,test_ip)
$(call run-unit-test,test_ip)
$(call make-unit-test,test_routing,test_routing,fd_waltz fd_util)
$(call make-unit-test,test_routing_load,test_routing_load,fd_waltz fd_util)
$(call make-unit-test,test_arp,test_arp,fd_waltz fd_util)

$(call run-unit-test,test_netlink)
$(call run-unit-test,test_routing)
endif
endif
