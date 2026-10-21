ifdef FD_HAS_HOSTED
$(call add-objs,fd_gossip_tile,fd_discof)
$(call add-objs,fd_gossvf_tile,fd_discof)
$(call make-fuzz-test,fuzz_gossvf_tile,fuzz_gossvf_tile,fd_disco fd_waltz fd_flamenco fd_ballet fd_tango fd_util)
$(call make-fuzz-test,fuzz_gossvf_gossip_pair,fuzz_gossvf_gossip_pair,fd_disco fd_waltz fd_flamenco fd_ballet fd_tango fd_util)
endif
