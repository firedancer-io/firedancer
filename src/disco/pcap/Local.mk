$(call add-hdrs,fd_pcap_replay.h)
$(call add-objs,fd_pcap_replay,fd_disco)
$(call make-unit-test,test_pcap_replay,test_pcap_replay,fd_disco fd_flamenco fd_tango fd_util)
$(call make-bin,fd_pcap_replay_tile,fd_pcap_replay_tile,fd_disco fd_flamenco fd_tango fd_util)
