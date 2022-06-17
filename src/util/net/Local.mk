$(call add-hdrs,fd_eth.h fd_ip4.h fd_igmp.h fd_udp.h)
$(call add-objs,fd_eth,fd_util)
$(call make-unit-test,test_eth,test_eth,fd_util)
$(call make-unit-test,test_ip4,test_ip4,fd_util)
$(call make-unit-test,test_igmp,test_igmp,fd_util)
$(call make-unit-test,test_udp,test_udp,fd_util)

