ifdef FD_HAS_INT128
ifdef FD_HAS_SECP256K1
$(call make-unit-test,test_consensus,test_consensus,fd_disco fd_choreo fd_flamenco fd_funk fd_tango fd_util fd_ballet fd_reedsol fd_waltz,$(SECP256K1_LIBS))
$(call make-unit-test,test_gossip_echo_vote,test_gossip_echo_vote,fd_disco fd_choreo fd_flamenco fd_funk fd_tango fd_util fd_ballet fd_reedsol fd_waltz,$(SECP256K1_LIBS))
endif
endif
