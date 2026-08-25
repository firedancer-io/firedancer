$(call add-hdrs,fd_gossip.h fd_gossip_message.h fd_crds.h fd_gossip_out.h fd_gossip_txbuild.h fd_gossip_purged.h fd_prune_finder.h)
$(call add-objs,fd_gossip fd_gossip_message fd_gossip_out fd_gossip_txbuild fd_gossip_purged fd_prune_finder,fd_flamenco)

$(call add-hdrs,fd_bloom.h fd_gossip_wsample.h)
$(call add-objs,fd_bloom fd_crds fd_active_set fd_ping_tracker fd_gossip_wsample,fd_flamenco)

$(call make-unit-test,test_bloom,test_bloom,fd_flamenco fd_ballet fd_util)
$(call run-unit-test,test_bloom)

$(call make-unit-test,test_active_set,test_active_set,fd_flamenco fd_ballet fd_util)
$(call run-unit-test,test_active_set)

$(call make-unit-test,test_ping_tracker,test_ping_tracker,fd_flamenco fd_ballet fd_util)
$(call run-unit-test,test_ping_tracker)

$(call make-unit-test,test_gossip_wsample,test_gossip_wsample,fd_flamenco fd_ballet fd_util)
$(call run-unit-test,test_gossip_wsample)

$(call make-unit-test,test_gossip_purged,test_gossip_purged,fd_flamenco fd_ballet fd_util)
$(call run-unit-test,test_gossip_purged)

ifdef FD_HAS_HOSTED
$(call make-fuzz-test,fuzz_gossip_message_serialize,fuzz_gossip_message_serialize,fd_flamenco fd_ballet fd_util)
endif
