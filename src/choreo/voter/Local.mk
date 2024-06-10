ifdef FD_HAS_INT128
$(call add-hdrs,fd_voter.h)
$(call add-objs,fd_voter,fd_choreo)
$(call make-unit-test,test_choreo_voter,test_choreo_voter,fd_disco fd_choreo fd_flamenco fd_funk fd_tango fd_util fd_ballet fd_reedsol fd_waltz,$(SECP256K1_LIBS))
endif
