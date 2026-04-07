$(call make-lib,fd_flamenco)
$(call add-hdrs,fd_flamenco_base.h fd_flamenco.h)
$(call add-hdrs,fd_rwlock.h)
$(call make-unit-test,test_rwlock,test_rwlock,fd_flamenco fd_util)
$(call run-unit-test,test_rwlock)
ifdef FD_HAS_RACESAN
$(call make-unit-test,test_rwlock_racesan,test_rwlock_racesan,fd_flamenco fd_util)
endif
