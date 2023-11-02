ifdef FD_HAS_INT128
$(call add-objs,fd_shred_dest,fd_disco)
$(call add-objs,fd_shredder,fd_disco)
$(call add-objs,fd_fec_resolver,fd_disco)
$(call add-objs,fd_stake_ci,fd_disco)
$(call make-unit-test,test_shred_dest,test_shred_dest,fd_ballet fd_util fd_flamenco fd_disco)
$(call make-unit-test,test_shredder,test_shredder,fd_ballet fd_util fd_flamenco fd_disco fd_reedsol)
$(call make-unit-test,test_fec_resolver,test_fec_resolver,fd_ballet fd_util fd_tango fd_flamenco fd_disco fd_reedsol)
$(call run-unit-test,test_shred_dest,)
$(call run-unit-test,test_shredder,)
$(call run-unit-test,test_fec_resolver,)
endif
