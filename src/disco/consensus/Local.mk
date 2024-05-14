ifdef FD_HAS_INT128
$(call make-unit-test,test_consensus,test_consensus,fd_disco fd_choreo fd_flamenco fd_funk fd_tango fd_util fd_ballet fd_reedsol fd_waltz,$(SECP256K1_LIBS))
$(call make-unit-test,test_vote_txn,test_vote_txn,fd_disco fd_choreo fd_flamenco fd_funk fd_tango fd_util fd_ballet fd_reedsol fd_waltz,$(SECP256K1_LIBS))
endif
