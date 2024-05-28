ifdef FD_HAS_INT128
$(call add-hdrs,fd_vote.h)
$(call add-objs,fd_vote,fd_choreo)
$(call make-unit-test,test_choreo_vote,test_choreo_vote,fd_disco fd_choreo fd_flamenco fd_funk fd_tango fd_util fd_ballet fd_reedsol fd_waltz,$(SECP256K1_LIBS))
endif
