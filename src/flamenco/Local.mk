$(call make-lib,fd_flamenco)
$(call add-hdrs,fd_flamenco_base.h fd_flamenco.h)
$(call add-objs,fd_flamenco,fd_flamenco)
$(call make-unit-test,test_flamenco,test_flamenco,fd_flamenco fd_ballet fd_util)
$(call run-unit-test,test_flamenco)

$(call add-hdrs,fd_rwlock.h)
