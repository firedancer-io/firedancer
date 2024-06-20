ifdef FD_HAS_INT128
$(call add-objs,fd_shred_dest,fd_disco)
$(call add-objs,fd_shredder,fd_disco)
$(call add-objs,fd_shred_cap,fd_disco,fd_flamenco)
$(call add-objs,fd_fec_resolver,fd_disco)
$(call add-objs,fd_stake_ci,fd_disco)
$(call make-unit-test,test_shred_dest,test_shred_dest,fd_disco fd_flamenco fd_ballet fd_util)
$(call make-unit-test,test_fec_resolver,test_fec_resolver,fd_flamenco fd_disco fd_ballet fd_util fd_tango fd_reedsol)
$(call make-unit-test,test_stake_ci,test_stake_ci,fd_disco fd_flamenco fd_ballet fd_util fd_tango fd_reedsol)
$(call run-unit-test,test_shred_dest,)
$(call run-unit-test,test_fec_resolver,)
$(call run-unit-test,test_stake_ci,)
ifdef FD_HAS_HOSTED
$(call make-unit-test,test_shredder,test_shredder,fd_disco fd_flamenco fd_ballet fd_util fd_reedsol)
$(call run-unit-test,test_shredder,)
endif
endif
