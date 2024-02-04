$(call add-hdrs,fd_eth.h fd_ip4.h fd_igmp.h fd_pcap.h fd_pcapng.h fd_udp.h)
$(call add-objs,fd_eth fd_ip4 fd_pcap fd_pcapng,fd_util)
$(call make-unit-test,test_eth,test_eth,fd_util)
$(call run-unit-test,test_eth)
$(call make-unit-test,test_ip4,test_ip4,fd_util)
$(call run-unit-test,test_ip4)
$(call make-unit-test,test_igmp,test_igmp,fd_util)
$(call run-unit-test,test_igmp)
$(call make-unit-test,test_udp,test_udp,fd_util)
$(call run-unit-test,test_udp)
$(call make-unit-test,test_pcap,test_pcap,fd_util)
ifdef FD_HAS_HOSTED
$(call make-unit-test,test_pcapng,test_pcapng,fd_util)
$(call run-unit-test,test_pcapng)
endif
$(call make-fuzz-test,fuzz_pcap,fuzz_pcap,fd_util)
$(call make-fuzz-test,fuzz_pcapng,fuzz_pcapng,fd_util)

